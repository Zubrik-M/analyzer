"""Rule dispatch and JSON finding construction."""

import ast
import fnmatch
from dataclasses import dataclass

from .flow import Flow, Value, EMPTY, merge
from .imports import Scope

TAINT_CONTEXTS = {'sql_tainted': 'sql', 'path_tainted': 'path',
                  'command_tainted': 'command', 'code_tainted': 'code'}


@dataclass(frozen=True)
class CheckContext:
    node: ast.AST
    name: str | None
    args: list
    keywords: dict
    match: dict
    value: Value


def argument(args, keywords, key=None, position=0):
    if isinstance(key, list):
        selected = [keywords[item] for item in key if item in keywords]
        return merge(*selected) if selected else (args[position] if position < len(args) else EMPTY)
    if key is not None and key in keywords:
        return keywords[key]
    return args[position] if position < len(args) else EMPTY


def matches_name(actual, pattern):
    if isinstance(pattern, list):
        return any(matches_name(actual, item) for item in pattern)
    return actual is not None and isinstance(pattern, str) and fnmatch.fnmatchcase(actual, pattern)


class Engine:
    def __init__(self, rules, source, filename):
        self.rules = rules
        self.source = source
        self.lines = source.splitlines()
        self.filename = filename
        self.findings = []
        self.seen = set()
        self.checked = 0
        self.parents = {}

    def emit(self, node, name, args, keywords, scope, target=None):
        kind = 'assignment' if target is not None else 'call'
        extra_kind = 'taint' if kind == 'call' else 'config'
        candidates = self.rules.index.get(kind, []) + self.rules.index.get(extra_kind, [])

        for rule in candidates:
            self.checked += 1
            match = rule['match']
            if not self._matches_candidate(kind, name, target, match):
                continue

            value = argument(args, keywords, match.get('keyword'), match.get('position', 0))
            context = CheckContext(node, name, args, keywords, match, value)
            if not PREDICATE_CHECKS[match['predicate']](self, context):
                continue

            key = (node.lineno, node.col_offset, rule['id'])
            if key in self.seen:
                continue

            self.seen.add(key)
            self.findings.append(self._finding(rule, context))

    @staticmethod
    def _matches_candidate(kind, name, target, match):
        if kind == 'call':
            return matches_name(name, match.get('function', ''))

        pattern = match.get('target', '')
        pattern = [item.lower() for item in pattern] if isinstance(pattern, list) else pattern.lower()
        if isinstance(target, ast.Name):
            name = target.id
        elif isinstance(target, ast.Attribute):
            name = target.attr
        elif isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
            name = str(target.slice.value)
        else:
            return False
        return matches_name(name.lower(), pattern)

    def _any_call(self, context):
        return True

    def _keyword_true(self, context):
        if context.match.get('skip_if_tainted_argument') and argument(
                context.args, context.keywords, ['args', 'command']).origins:
            return False

        return context.match['keyword'] in context.keywords and context.value.literal is True

    def _keyword_false(self, context):
        return context.match['keyword'] in context.keywords and context.value.literal is False

    def _string_literal(self, context):
        return isinstance(context.value.literal, str) and bool(context.value.literal)

    def _secret_literal(self, context):
        literal = context.value.literal
        return (isinstance(literal, str) and len(literal) >= 8 and
                literal.lower() not in self.rules.example_secrets)

    def _debug_true(self, context):
        return context.value.literal is True

    def _tainted(self, context):
        predicate = context.match['predicate']
        category = TAINT_CONTEXTS.get(predicate, context.match.get('context', ''))
        if not context.value.origins or category in context.value.sanitized:
            return False

        if predicate == 'command_tainted' and context.name and context.name.startswith('subprocess.'):
            shell = context.keywords.get('shell', EMPTY)
            return shell.literal is True or context.name in {'subprocess.getoutput', 'subprocess.getstatusoutput'}

        return True

    def _context_has(self, node, words):
        current = node
        while current in self.parents and not isinstance(current, ast.stmt):
            current = self.parents[current]
        identifiers = []
        for child in ast.walk(current):
            if isinstance(child, ast.Name):
                identifiers.append(child.id.lower())
            elif isinstance(child, ast.Attribute):
                identifiers.append(child.attr.lower())
            elif isinstance(child, ast.Constant) and isinstance(child.value, str):
                identifiers.append(child.value.lower())
        return any(word in identifier for word in words for identifier in identifiers)

    @staticmethod
    def _weak_algorithm(context):
        if context.name in ('hashlib.md5', 'hashlib.sha1'):
            return True
        if context.name == 'hashlib.new' and context.node.args:
            first = context.node.args[0]
            return isinstance(first, ast.Constant) and isinstance(first.value, str) and first.value.lower() in {'md5', 'sha1'}
        return False

    def _weak_hash(self, context):
        return self._weak_algorithm(context) and self._context_has(context.node, self.rules.hash_context)

    def _weak_crypto(self, context):
        return self._weak_algorithm(context) and self._context_has(context.node, self.rules.crypto_context)

    def _random_secret(self, context):
        return self._context_has(context.node, self.rules.random_context)

    def _yaml_unsafe(self, context):
        loader_nodes = [item.value for item in context.node.keywords if item.arg == 'Loader']
        if len(context.node.args) > 1:
            loader_nodes.append(context.node.args[1])

        return not any(isinstance(item, (ast.Name, ast.Attribute)) and
                       (item.id if isinstance(item, ast.Name) else item.attr) in {'SafeLoader', 'CSafeLoader'}
                       for item in loader_nodes)

    def _finding(self, rule, context):
        node = context.node
        finding = {
            'file': self.filename, 'line': node.lineno, 'column': node.col_offset + 1,
            'rule_id': rule['id'], 'type': rule['name'], 'category': rule.get('category', rule['name']),
            'cwe': rule['cwe'], 'severity': rule['severity'],
            'description': rule['description'], 'message': rule['description'],
            'code': (ast.get_source_segment(self.source, node) or self.lines[node.lineno - 1]).strip(),
            'recommendation': rule['recommendation'],
        }

        if context.value.origins:
            origin = sorted(context.value.origins, key=lambda item: (item.line, item.name))[0]
            finding['taint'] = {'source': origin.name, 'source_line': origin.line,
                                'chain': list(origin.chain), 'sink': context.name,
                                'sanitized_for': sorted(context.value.sanitized)}

        return finding

    def analyze(self, tree):
        self.parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        Flow(self.rules, self.emit).block(tree.body, Scope())
        self.findings.sort(key=lambda x: (x['line'], x['column'], x['rule_id']))

        return self.findings


PREDICATE_CHECKS = {
    'any_call': Engine._any_call,
    'keyword_true': Engine._keyword_true,
    'keyword_false': Engine._keyword_false,
    'string_literal': Engine._string_literal,
    'secret_literal': Engine._secret_literal,
    'debug_true': Engine._debug_true,
    'tainted': Engine._tainted,
    'sql_tainted': Engine._tainted,
    'path_tainted': Engine._tainted,
    'command_tainted': Engine._tainted,
    'code_tainted': Engine._tainted,
    'weak_hash': Engine._weak_hash,
    'weak_crypto': Engine._weak_crypto,
    'random_secret': Engine._random_secret,
    'yaml_unsafe': Engine._yaml_unsafe,
    'unsafe_temp': Engine._any_call,
}

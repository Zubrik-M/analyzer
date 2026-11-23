"""Intrafile, path-insensitive abstract interpretation of Python AST.

Values carry source locations and context-specific sanitation. Branch joins use
may-taint union; loops execute one abstract iteration and join with entry.
"""
import ast
from dataclasses import dataclass, field

from .imports import Scope, dotted


@dataclass(frozen=True)
class Origin:
    name: str
    line: int
    chain: tuple = ()


@dataclass(frozen=True)
class Value:
    origins: frozenset = field(default_factory=frozenset)
    sanitized: frozenset = field(default_factory=frozenset)
    literal: object = None

    def step(self, label):
        return Value(frozenset(Origin(o.name, o.line, o.chain + (label,)) for o in self.origins), self.sanitized, self.literal)


EMPTY = Value()


def merge(*values):
    values = [v for v in values if v is not None]
    origins = frozenset().union(*(v.origins for v in values))

    tainted = [v for v in values if v.origins]
    sanitized = frozenset.intersection(*(v.sanitized for v in tainted)) if tainted else frozenset()

    literal = values[0].literal if len(values) == 1 else None

    return Value(origins, sanitized, literal)


class Flow:
    def __init__(self, rules, emit):
        self.rules = rules
        self.emit = emit
        self.active = set()

    def function_scope(self, fn, parent):
        local = Scope(parent)
        globals_ = set()
        bound = set()

        def visit(node):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bound.add(node.name)
                return

            if isinstance(node, (ast.Global, ast.Nonlocal)):
                globals_.update(node.names)
                return

            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                bound.add(node.id)

            for child in ast.iter_child_nodes(node):
                visit(child)

        for stmt in fn.body:
            visit(stmt)

        local.shadowed.update(bound - globals_)

        return local


    def expression(self, node, scope, depth=0):
        if node is None:
            return EMPTY

        if isinstance(node, ast.Constant):
            return Value(literal=node.value)

        if isinstance(node, ast.Name):
            return scope.value(node.id) or EMPTY

        if isinstance(node, ast.NamedExpr):
            value = self.expression(node.value, scope, depth)
            self.assign(node.target, value, scope)
            self.emit(node, None, [value], {}, scope, target=node.target)
            return value

        if isinstance(node, (ast.Attribute, ast.Subscript)):
            name = dotted(node, scope) if isinstance(node, ast.Attribute) else dotted(node.value, scope)
            if name in self.rules.sources:
                return Value(frozenset({Origin(name, node.lineno)}))

            stored = scope.value(name) if name else None
            if stored is not None:
                return stored

            return self.expression(node.value, scope, depth)

        if isinstance(node, ast.Call):
            name = dotted(node.func, scope)
            args = [self.expression(x, scope, depth) for x in node.args]
            keywords = {k.arg: self.expression(k.value, scope, depth) for k in node.keywords if k.arg is not None}
            starred_kwargs = [self.expression(k.value, scope, depth) for k in node.keywords if k.arg is None]
            self.emit(node, name, args, keywords, scope)
            if name in self.rules.sources:
                return Value(frozenset({Origin(name, node.lineno)}))

            receiver = self.expression(node.func.value, scope, depth) if isinstance(node.func, ast.Attribute) else EMPTY
            combined = merge(receiver, *args, *keywords.values(), *starred_kwargs)

            for context, names in self.rules.sanitizers.items():
                if name in names:
                    return Value(combined.origins, combined.sanitized | {context})

            if isinstance(node.func, (ast.Name, ast.Attribute)):
                fn = scope.function(node.func.id if isinstance(node.func, ast.Name) else node.func.attr)
                candidates = fn if isinstance(fn, tuple) else (fn,)
                results = []
                for candidate in candidates:
                    if candidate is None or depth >= 3 or id(candidate) in self.active:
                        continue
                    fn = candidate
                    local = self.function_scope(fn, scope)
                    params = fn.args.posonlyargs + fn.args.args
                    defaults = [EMPTY] * (len(params) - len(fn.args.defaults)) + [self.expression(x, scope, depth) for x in fn.args.defaults]
                    call_args = ([receiver] if isinstance(node.func, ast.Attribute) else []) + args
                    for index, param in enumerate(params):
                        local.bind(param.arg, keywords.get(param.arg, call_args[index] if index < len(call_args) else defaults[index]).step(param.arg))

                    for param, default in zip(fn.args.kwonlyargs, fn.args.kw_defaults):
                        value = keywords.get(param.arg)
                        if value is None:
                            value = self.expression(default, scope, depth)
                        local.bind(param.arg, value.step(param.arg))

                    if fn.args.vararg:
                        local.bind(fn.args.vararg.arg, merge(*call_args[len(params):]))

                    if fn.args.kwarg:
                        names = {param.arg for param in params + fn.args.kwonlyargs}
                        local.bind(fn.args.kwarg.arg, merge(*(value for key, value in keywords.items() if key not in names), *starred_kwargs))

                    self.active.add(id(fn))
                    try:
                        results.extend(self.block(fn.body, local, depth + 1))
                    finally:
                        self.active.remove(id(fn))
                if results:
                    return merge(*results)

            return combined

        if isinstance(node, ast.JoinedStr):
            return merge(*(self.expression(x, scope, depth) for x in node.values))

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.expression(node.left, scope, depth)
            right = self.expression(node.right, scope, depth)
            if isinstance(left.literal, str) and isinstance(right.literal, str):
                return Value(left.origins | right.origins, left.sanitized & right.sanitized,
                             left.literal + right.literal)
            return merge(left, right)

        if isinstance(node, (ast.BinOp, ast.BoolOp, ast.Compare, ast.IfExp)):
            return merge(*(self.expression(x, scope, depth) for x in ast.iter_child_nodes(node) if isinstance(x, ast.expr)))

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return merge(*(self.expression(x, scope, depth) for x in node.elts))

        if isinstance(node, ast.Dict):
            return merge(*(self.expression(x, scope, depth) for x in node.keys + node.values if x is not None))

        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            local = Scope(scope)
            for generator in node.generators:
                value = self.expression(generator.iter, local, depth)
                self.assign(generator.target, value, local)
                for condition in generator.ifs:
                    self.expression(condition, local, depth)

            if isinstance(node, ast.DictComp):
                return merge(self.expression(node.key, local, depth), self.expression(node.value, local, depth))

            return self.expression(node.elt, local, depth)

        if isinstance(node, (ast.UnaryOp, ast.Starred, ast.Await)):
            return self.expression(node.operand if hasattr(node, 'operand') else node.value, scope, depth)

        return merge(*(self.expression(x, scope, depth) for x in ast.iter_child_nodes(node) if isinstance(x, ast.expr)))


    def assign(self, target, value, scope):
        if isinstance(target, ast.Name):
            scope.bind(target.id, value.step(target.id))

        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            name = dotted(target, scope) if isinstance(target, ast.Attribute) else dotted(target.value, scope)
            if name:
                scope.values[name] = value.step(name)

        elif isinstance(target, ast.Starred):
            self.assign(target.value, value, scope)

        elif isinstance(target, (ast.Tuple, ast.List)):
            for part in target.elts:
                self.assign(part, value, scope)


    def join_scope(self, target, branches):
        names = set().union(*(s.values.keys() for s in branches))

        for name in names:
            vals = [s.values.get(name, target.value(name) or EMPTY) for s in branches]
            target.bind(name, merge(*vals))

        aliases = {}
        for name in set().union(*(branch.aliases for branch in branches)):
            values = [branch.aliases.get(name) for branch in branches]
            if all(value is not None and value == values[0] for value in values):
                aliases[name] = values[0]

        functions = {}
        for name in set().union(*(branch.functions for branch in branches)):
            values = [branch.functions.get(name) for branch in branches]
            if any(value is not None for value in values):
                functions[name] = tuple(dict.fromkeys(fn for value in values for fn in (value if isinstance(value, tuple) else (value,))))

        target.aliases = aliases
        target.functions = functions
        target.shadowed.update(set().union(*(branch.shadowed for branch in branches)))


    def apply_allowlist(self, test, branch):
        if not isinstance(test, ast.Compare) or len(test.ops) != 1 or not isinstance(test.ops[0], ast.In):
            return

        if not isinstance(test.left, ast.Name) or len(test.comparators) != 1:
            return

        collection = test.comparators[0]
        if not isinstance(collection, (ast.Tuple, ast.List, ast.Set)) or not collection.elts:
            return

        if not all(isinstance(item, ast.Constant) and isinstance(item.value, (str, int)) for item in collection.elts):
            return

        value = branch.value(test.left.id)
        if value and value.origins:
            branch.bind(test.left.id, Value(value.origins,
                         value.sanitized | {'command', 'sql', 'path', 'code'}, value.literal))


    def bind_pattern(self, pattern, value, scope):
        if isinstance(pattern, (ast.MatchAs, ast.MatchStar)) and pattern.name:
            scope.bind(pattern.name, value.step(pattern.name))

        if isinstance(pattern, ast.MatchMapping) and pattern.rest:
            scope.bind(pattern.rest, value.step(pattern.rest))

        for child in ast.iter_child_nodes(pattern):
            if isinstance(child, ast.pattern):
                self.bind_pattern(child, value, scope)



    def block(self, body, scope, depth=0):
        returns = []

        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scope.functions[stmt.name] = stmt

        for stmt in body:
            handler = getattr(self, f'statement_{type(stmt).__name__}', None)
            if handler:
                result = handler(stmt, scope, depth)
                if result:
                    returns.extend(result)

        return returns

    def statement_Import(self, stmt, scope, depth):
        scope.import_node(stmt)

    statement_ImportFrom = statement_Import

    def statement_FunctionDef(self, stmt, scope, depth):
        scope.bind(stmt.name, EMPTY)
        scope.functions[stmt.name] = stmt

        if depth == 0:
            child = self.function_scope(stmt, scope)
            for arg in stmt.args.posonlyargs + stmt.args.args + stmt.args.kwonlyargs:
                child.bind(arg.arg, EMPTY)

            self.block(stmt.body, child, depth + 1)

    statement_AsyncFunctionDef = statement_FunctionDef

    def statement_ClassDef(self, stmt, scope, depth):
        for base in stmt.bases:
            self.expression(base, scope, depth)

        for keyword in stmt.keywords:
            self.expression(keyword.value, scope, depth)

        for decorator in stmt.decorator_list:
            self.expression(decorator, scope, depth)

        self.block(stmt.body, Scope(scope), 0)
        scope.bind(stmt.name, EMPTY)

    def statement_Assign(self, stmt, scope, depth):
        value = self.expression(stmt.value, scope, depth)

        for target in stmt.targets:
            self.assign(target, value, scope)
            self.emit(stmt, None, [value], {}, scope, target=target)

    def statement_AnnAssign(self, stmt, scope, depth):
        if stmt.value is None:
            return
        value = self.expression(stmt.value, scope, depth)
        self.assign(stmt.target, value, scope)
        self.emit(stmt, None, [value], {}, scope, target=stmt.target)

    def statement_AugAssign(self, stmt, scope, depth):
        value = merge(self.expression(stmt.target, scope, depth),
                      self.expression(stmt.value, scope, depth))
        self.assign(stmt.target, value, scope)

    def statement_If(self, stmt, scope, depth):
        self.expression(stmt.test, scope, depth)
        returns = []
        branches = []

        for index, arm in enumerate((stmt.body, stmt.orelse)):
            branch = scope.clone()
            if index == 0:
                self.apply_allowlist(stmt.test, branch)

            returns.extend(self.block(arm, branch, depth))
            branches.append(branch)

        self.join_scope(scope, branches)
        return returns

    def statement_Try(self, stmt, scope, depth):
        returns = []
        branches = []
        success = scope.clone()
        returns.extend(self.block(stmt.body + stmt.orelse, success, depth))
        branches.append(success)
        for handler in stmt.handlers:
            for count in range(len(stmt.body) + 1):
                branch = scope.clone()
                self.block(stmt.body[:count], branch, depth)
                returns.extend(self.block(handler.body, branch, depth))
                branches.append(branch)

        self.join_scope(scope, branches)
        returns.extend(self.block(stmt.finalbody, scope, depth))
        return returns

    def statement_Match(self, stmt, scope, depth):
        subject = self.expression(stmt.subject, scope, depth)
        returns = []
        branches = [scope.clone()]

        for case in stmt.cases:
            branch = scope.clone()
            self.bind_pattern(case.pattern, subject, branch)

            if case.guard:
                self.expression(case.guard, branch, depth)

            returns.extend(self.block(case.body, branch, depth))
            branches.append(branch)

        self.join_scope(scope, branches)
        return returns

    def statement_Loop(self, stmt, scope, depth):
        branch = scope.clone()

        if isinstance(stmt, ast.While):
            self.expression(stmt.test, branch, depth)
        else:
            value = self.expression(stmt.iter, branch, depth)
            self.assign(stmt.target, value, branch)

        returns = self.block(stmt.body, branch, depth)
        self.join_scope(scope, [scope.clone(), branch])
        returns.extend(self.block(stmt.orelse, scope, depth))
        return returns

    statement_For = statement_Loop
    statement_AsyncFor = statement_Loop
    statement_While = statement_Loop

    def statement_Return(self, stmt, scope, depth):
        return [self.expression(stmt.value, scope, depth)]

    def statement_Expr(self, stmt, scope, depth):
        self.expression(stmt.value, scope, depth)

    def statement_With(self, stmt, scope, depth):
        for item in stmt.items:
            value = self.expression(item.context_expr, scope, depth)
            if item.optional_vars:
                self.assign(item.optional_vars, value, scope)

        return self.block(stmt.body, scope, depth)

    statement_AsyncWith = statement_With

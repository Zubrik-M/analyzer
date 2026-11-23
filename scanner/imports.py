"""Lexical name resolution with local shadowing."""

import ast


def dotted(node, scope):
    if isinstance(node, ast.Name):
        return scope.resolve(node.id)

    if isinstance(node, ast.Attribute):
        parent = dotted(node.value, scope)
        return f"{parent}.{node.attr}" if parent else None

    if isinstance(node, ast.Call):
        parent = dotted(node.func, scope)
        return f"<call:{parent}>" if parent else None

    return None


class Scope:
    def __init__(self, parent=None):
        self.parent = parent
        self.values = {}
        self.aliases = {}
        self.shadowed = set()
        self.functions = {}

    def resolve(self, name):
        if name in self.aliases:
            return self.aliases[name]

        if name in self.shadowed:
            return f'<local:{name}>'

        return self.parent.resolve(name) if self.parent else name

    def value(self, name):
        if name in self.values:
            return self.values[name]

        if name in self.shadowed:
            return None

        return self.parent.value(name) if self.parent else None

    def function(self, name):
        if name in self.functions:
            return self.functions[name]

        if name in self.shadowed:
            return None

        return self.parent.function(name) if self.parent else None

    def bind(self, name, value):
        self.shadowed.add(name)
        self.aliases.pop(name, None)
        self.functions.pop(name, None)
        self.values[name] = value

    def clone(self):
        other = Scope(self.parent)
        other.values = self.values.copy()
        other.aliases = self.aliases.copy()
        other.shadowed = self.shadowed.copy()
        other.functions = self.functions.copy()

        return other

    def import_node(self, node):
        if isinstance(node, ast.Import):
            pairs = ((a.asname or a.name.split('.')[0], a.name if a.asname else a.name.split('.')[0]) for a in node.names)
        else:
            module = '.' * node.level + (node.module or '')
            pairs = ((a.asname or a.name, f"{module}.{a.name}") for a in node.names if a.name != '*')

        for alias, full in pairs:
            self.aliases[alias] = full
            self.shadowed.add(alias)
            self.values.pop(alias, None)
            self.functions.pop(alias, None)

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
    def __init__(self, parent=None, kind='block'):
        self.parent = parent
        self.kind = kind
        self.values = {}
        self.aliases = {}
        self.shadowed = set()
        self.functions = {}
        self.globals = set()
        self.nonlocals = set()

    def module(self):
        scope = self
        while scope.parent is not None:
            scope = scope.parent
        return scope

    def owner(self, name):
        if name in self.globals:
            return self.module()
        if name in self.nonlocals:
            scope = self.parent
            while scope is not None:
                if scope.kind == 'function' and name in scope.shadowed:
                    return scope
                scope = scope.parent
        return self

    def resolve(self, name):
        owner = self.owner(name)
        if owner is not self:
            return owner.resolve(name)
        if name in self.aliases:
            return self.aliases[name]

        if name in self.shadowed:
            return f'<local:{name}>'

        return self.parent.resolve(name) if self.parent else name

    def value(self, name):
        owner = self.owner(name)
        if owner is not self:
            return owner.value(name)
        if name in self.values:
            return self.values[name]

        if name in self.shadowed:
            return None

        return self.parent.value(name) if self.parent else None

    def function(self, name):
        owner = self.owner(name)
        if owner is not self:
            return owner.function(name)
        if name in self.functions:
            return self.functions[name]

        if name in self.shadowed:
            return None

        return self.parent.function(name) if self.parent else None

    def bind(self, name, value):
        owner = self.owner(name)
        if owner is not self:
            owner.bind(name, value)
            return
        self.shadowed.add(name)
        self.aliases.pop(name, None)
        self.functions.pop(name, None)
        self.values[name] = value

    def clone(self, deep=False):
        other = Scope(self.parent.clone(deep=True) if deep and self.parent else self.parent, self.kind)
        other.values = self.values.copy()
        other.aliases = self.aliases.copy()
        other.shadowed = self.shadowed.copy()
        other.functions = self.functions.copy()
        other.globals = self.globals.copy()
        other.nonlocals = self.nonlocals.copy()

        return other

    def import_node(self, node):
        if isinstance(node, ast.Import):
            pairs = ((a.asname or a.name.split('.')[0], a.name if a.asname else a.name.split('.')[0]) for a in node.names)
        else:
            module = '.' * node.level + (node.module or '')
            pairs = ((a.asname or a.name, f"{module}.{a.name}") for a in node.names if a.name != '*')

        for alias, full in pairs:
            owner = self.owner(alias)
            owner.aliases[alias] = full
            owner.shadowed.add(alias)
            owner.values.pop(alias, None)
            owner.functions.pop(alias, None)

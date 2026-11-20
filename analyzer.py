"""Small AST-based demonstrator for the course project."""

import argparse
import ast
import json
import os
from pathlib import Path

import yaml


EXCLUDED_DIRECTORIES = {".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__"}
SEVERITIES = {"low", "medium", "high"}
RULE_FIELDS = {"id", "name", "cwe", "severity", "description", "recommendation", "match"}
MATCH_FIELDS = {
    ("call", "keyword_true"): {"kind", "predicate", "function", "keyword"},
    ("call", "any_call"): {"kind", "predicate", "function"},
    ("assignment", "string_literal"): {"kind", "predicate", "target"},
}


def qualified_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = qualified_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def load_rules(path):
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"rules"} or not isinstance(data["rules"], list):
        raise ValueError("YAML must contain a 'rules' list")
    rules = data["rules"]
    seen = set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != RULE_FIELDS or not isinstance(rule.get("match"), dict):
            raise ValueError("Each rule must contain a 'match' mapping")
        for key in ("id", "name", "cwe", "severity", "description", "recommendation"):
            if not isinstance(rule.get(key), str) or not rule[key].strip():
                raise ValueError(f"Missing or invalid rule field: {key}")
        if rule["id"] in seen:
            raise ValueError(f"Duplicate rule ID: {rule['id']}")
        seen.add(rule["id"])
        severity = rule["severity"].lower()
        if severity not in SEVERITIES:
            raise ValueError(f"Invalid severity in {rule['id']}: {rule['severity']}")
        rule["severity"] = severity
        match = rule["match"]
        kind, predicate = match.get("kind"), match.get("predicate")
        if not isinstance(kind, str) or not isinstance(predicate, str):
            raise ValueError(f"Unsupported match in {rule['id']}")
        fields = MATCH_FIELDS.get((kind, predicate))
        if fields is None or set(match) != fields:
            raise ValueError(f"Unsupported match in {rule['id']}")
        for key in fields - {"kind", "predicate"}:
            if not isinstance(match[key], str) or not match[key].strip():
                raise ValueError(f"Invalid {key} in {rule['id']}")
    return rules


def match_node(node, match):
    kind, predicate = match["kind"], match["predicate"]
    if kind == "call":
        if not isinstance(node, ast.Call) or qualified_name(node.func) != match["function"]:
            return False
        if predicate == "keyword_true":
            return any(k.arg == match.get("keyword") and isinstance(k.value, ast.Constant)
                       and k.value.value is True for k in node.keywords)
        if predicate == "any_call":
            return True
        return False
    if kind == "assignment":
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            return False
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value
        return (any(isinstance(t, ast.Name) and t.id == match["target"] for t in targets)
                and predicate == "string_literal" and isinstance(value, ast.Constant)
                and isinstance(value.value, str) and bool(value.value))
    return False


def analyze_file(path, rules, base):
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    relative = path.relative_to(base).as_posix()
    findings = []
    for node in ast.walk(tree):
        for rule in rules:
            if match_node(node, rule["match"]):
                findings.append({
                    "file": relative, "line": node.lineno, "column": node.col_offset + 1,
                    "rule_id": rule["id"], "type": rule["name"],
                    "cwe": rule["cwe"], "severity": rule["severity"],
                    "description": rule["description"],
                    "recommendation": rule["recommendation"],
                })
    return findings


def analyze(target, rules):
    target = Path(target).resolve()
    if not target.exists():
        raise ValueError(f"Path does not exist: {target}")
    if not target.is_file() and not target.is_dir():
        raise ValueError("Input must be a Python file or directory")
    if target.is_file() and target.suffix != ".py":
        raise ValueError("Input file must have .py extension")
    base = target.parent if target.is_file() else target
    if target.is_file():
        paths = [target]
    else:
        paths = []
        for directory, subdirs, files in os.walk(target):
            subdirs[:] = sorted(d for d in subdirs if d not in EXCLUDED_DIRECTORIES)
            paths.extend(Path(directory) / name for name in sorted(files) if name.endswith(".py"))
        paths.sort()
    findings, errors = [], []
    for path in paths:
        try:
            findings.extend(analyze_file(path, rules, base))
        except (SyntaxError, UnicodeError, OSError) as exc:
            errors.append({"file": path.relative_to(base).as_posix(), "error": str(exc)})
    findings.sort(key=lambda x: (x["file"], x["line"], x["column"], x["rule_id"]))
    errors.sort(key=lambda x: x["file"])
    return {"schema_version": "1.0", "summary": {"files_scanned": len(paths),
            "findings": len(findings), "errors": len(errors)}, "findings": findings, "errors": errors}


def main():
    parser = argparse.ArgumentParser(description="Demonstration AST security scanner")
    parser.add_argument("target", help="Python file or directory")
    parser.add_argument("--rules", default=str(Path(__file__).with_name("rules.yaml")))
    parser.add_argument("--output", help="Write JSON to this file; otherwise print to stdout")
    args = parser.parse_args()
    try:
        report = analyze(args.target, load_rules(args.rules))
        output = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
        else:
            print(output, end="")
    except (ValueError, OSError, yaml.YAMLError) as exc:
        parser.exit(2, f"Error: {exc}\n")


if __name__ == "__main__":
    main()

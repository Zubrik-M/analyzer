"""Rule loading and validation; YAML is data, never executable code."""

from collections import defaultdict
from pathlib import Path

import yaml

SEVERITIES = {"low", "medium", "high", "critical"}
KINDS = {"call", "assignment", "taint", "config"}
PREDICATES = {"any_call", "keyword_true", "string_literal", "tainted", "keyword_false", "weak_hash", "weak_crypto", "secret_literal", "debug_true", "random_secret", "unsafe_temp", "yaml_unsafe", "sql_tainted", "path_tainted", "command_tainted", "code_tainted"}
REQUIRED = {"id", "name", "cwe", "severity", "description", "recommendation", "match"}
MATCH_KEYS = {'kind', 'predicate', 'function', 'target', 'keyword', 'position',
              'context', 'skip_if_tainted_argument'}


class RuleSet(list):
    def __init__(self, rules, sources=(), sanitizers=None, contexts=None):
        super().__init__(rules)
        self.sources = tuple(sources)
        self.sanitizers = sanitizers or {}
        contexts = contexts or {}
        self.example_secrets = frozenset(contexts.get('example_secrets', []))
        self.hash_context = tuple(contexts.get('hash', []))
        self.crypto_context = tuple(contexts.get('crypto', []))
        self.random_context = tuple(contexts.get('random', []))
        self.index = defaultdict(list)

        for rule in rules:
            self.index[rule["match"]["kind"]].append(rule)


def load_rules(path):
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ValueError("YAML должен содержать список 'rules'")

    if any(k not in {"rules", "sources", "sanitizers", "contexts"} for k in data):
        raise ValueError('Неизвестное поле верхнего уровня в YAML')

    sources = data.get("sources", [])
    sanitizers = data.get("sanitizers", {})
    contexts = data.get('contexts', {})
    if (not isinstance(contexts, dict) or set(contexts) - {'example_secrets', 'hash', 'crypto', 'random'} or
            any(not isinstance(values, list) or not all(isinstance(item, str) for item in values)
                for values in contexts.values())):
        raise ValueError("Поле 'contexts' должно содержать списки строк")

    if not isinstance(sources, list) or not all(isinstance(x, str) for x in sources):
        raise ValueError("Поле 'sources' должно быть списком имён")

    if not isinstance(sanitizers, dict) or not all(isinstance(k, str) and isinstance(v, list) and all(isinstance(x, str) for x in v) for k, v in sanitizers.items()):
        raise ValueError("Поле 'sanitizers' должно содержать списки имён по контекстам")

    seen = set()

    for rule in data["rules"]:
        if not isinstance(rule, dict) or not REQUIRED <= rule.keys() or not isinstance(rule["match"], dict):
            raise ValueError("Каждое правило должно содержать обязательные поля и объект 'match'")

        if set(rule) - REQUIRED - {'category'}:
            raise ValueError(f"Неизвестное поле в правиле {rule['id']}")

        for key in REQUIRED - {"match"}:
            if not isinstance(rule[key], str) or not rule[key].strip():
                raise ValueError(f"Некорректное поле правила: {key}")

        if rule["id"] in seen:
            raise ValueError(f"Повторяется идентификатор правила: {rule['id']}")

        seen.add(rule["id"])
        rule["severity"] = rule["severity"].lower()

        if rule["severity"] not in SEVERITIES:
            raise ValueError(f"Некорректный уровень опасности: {rule['id']}")

        match = rule["match"]
        if set(match) - MATCH_KEYS:
            raise ValueError(f"Неизвестное поле условия в правиле {rule['id']}")

        kind, predicate = match.get("kind"), match.get("predicate")
        if not isinstance(kind, str) or kind not in KINDS or not isinstance(predicate, str) or predicate not in PREDICATES:
            raise ValueError(f"Неподдерживаемое условие в правиле {rule['id']}")

        if kind in {"call", "taint"} and not (isinstance(match.get("function"), str) or
                isinstance(match.get("function"), list) and match["function"] and
                all(isinstance(x, str) for x in match["function"])):
            raise ValueError(f"Не указана функция в правиле {rule['id']}")

        if kind in {"assignment", "config"} and not (isinstance(match.get("target"), str) or isinstance(match.get("target"), list) and all(isinstance(x, str) for x in match["target"])):
            raise ValueError(f"Не указана цель в правиле {rule['id']}")

        if kind in {'call', 'taint'} and predicate in {'string_literal', 'secret_literal', 'debug_true'}:
            raise ValueError(f"Некорректное условие вызова в правиле {rule['id']}")

        if kind in {'assignment', 'config'} and predicate not in {'string_literal', 'secret_literal', 'debug_true'}:
            raise ValueError(f"Некорректное условие присваивания в правиле {rule['id']}")

        if predicate in {"keyword_true", "keyword_false"} and not isinstance(match.get("keyword"), str):
            raise ValueError(f"Не указан именованный аргумент в правиле {rule['id']}")

        if 'keyword' in match and predicate not in {'keyword_true', 'keyword_false'} and not (
                isinstance(match['keyword'], str) or isinstance(match['keyword'], list) and
                match['keyword'] and all(isinstance(x, str) for x in match['keyword'])):
            raise ValueError(f"Некорректный именованный аргумент в правиле {rule['id']}")

        if 'skip_if_tainted_argument' in match:
            if predicate != 'keyword_true' or not isinstance(match['skip_if_tainted_argument'], bool):
                raise ValueError(f"Некорректный параметр пропуска в правиле {rule['id']}")

        if 'position' in match and (not isinstance(match['position'], int) or isinstance(match['position'], bool) or match['position'] < 0):
            raise ValueError(f"Некорректная позиция аргумента в правиле {rule['id']}")

        if any(not isinstance(v, (str, int, bool, list)) for v in match.values()):
            raise ValueError(f"Некорректное значение условия в правиле {rule['id']}")

    return RuleSet(data["rules"], sources, sanitizers, contexts)

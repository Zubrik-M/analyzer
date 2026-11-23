"""Проверка Python-кода по YAML-правилам и консольный запуск."""

import argparse
import ast
import json
import os
from pathlib import Path

import yaml

try:
    from .scanner.engine import Engine
    from .scanner.rules import load_rules

except ImportError:  # direct script execution
    from scanner.engine import Engine
    from scanner.rules import load_rules

EXCLUDED_DIRECTORIES = {'.git', '.hg', '.svn', '.venv', 'venv', 'env', '__pycache__', '.mypy_cache', '.pytest_cache', 'node_modules', 'build', 'dist'}


def analyze_file(path, rules, base):
    source = Path(path).read_text(encoding='utf-8')
    tree = ast.parse(source, filename=str(path))
    engine = Engine(rules, source, Path(path).relative_to(base).as_posix())
    return engine.analyze(tree)


def analyze(target, rules):
    target = Path(target).resolve()
    if not target.exists():
        raise ValueError(f'Путь не существует: {target}')

    if not target.is_file() and not target.is_dir():
        raise ValueError('Укажите файл Python или папку')

    if target.is_file() and target.suffix != '.py':
        raise ValueError('Файл должен иметь расширение .py')

    base = target.parent if target.is_file() else target
    paths = [target] if target.is_file() else []

    if target.is_dir():
        for directory, subdirs, files in os.walk(target):
            subdirs[:] = sorted(d for d in subdirs if d not in EXCLUDED_DIRECTORIES)
            paths.extend(Path(directory) / name for name in sorted(files) if name.endswith('.py'))
        paths.sort()

    findings, errors = [], []

    for path in paths:
        try:
            findings.extend(analyze_file(path, rules, base))
        except (SyntaxError, UnicodeError, OSError) as exc:
            errors.append({'file': path.relative_to(base).as_posix(), 'error': str(exc)})

    findings.sort(key=lambda x: (x['file'], x['line'], x['column'], x['rule_id']))
    errors.sort(key=lambda x: x['file'])

    return {'schema_version': '1.0',
            'summary': {'files_scanned': len(paths), 'findings': len(findings), 'errors': len(errors)},
            'findings': findings, 'errors': errors}


def interactive(rules_path):
    project_dir = Path(__file__).resolve().parent
    rules = load_rules(rules_path)
    severity_names = {'low': 'НИЗКИЙ', 'medium': 'СРЕДНИЙ',
                      'high': 'ВЫСОКИЙ', 'critical': 'КРИТИЧЕСКИЙ'}

    print('Анализатор Python-кода')
    print(f'Рабочая папка: {project_dir}')
    print('Введите путь к файлу или папке. Enter — проверить примеры, 0 — выход.')

    while True:
        try:
            entered = input('\nПуть [примеры]: ').strip()
            if entered == '0':
                return

            target = Path(entered or 'examples').expanduser()

            if not target.is_absolute():
                target = project_dir / target

            report = analyze(target, rules)
            summary = report['summary']

            print(f"\nПроверено файлов: {summary['files_scanned']} | "
                  f"предупреждений: {summary['findings']} | ошибок: {summary['errors']}")

            for finding in report['findings']:
                print(f"\n[{severity_names.get(finding['severity'], finding['severity'].upper())}] "
                      f"{finding['file']}:{finding['line']}:{finding['column']} "
                      f"{finding['rule_id']} — {finding['type']}")
                print(f"  {finding['code']}")
                print(f"  Совет: {finding['recommendation']}")

            for error in report['errors']:
                print(f"\n[ОШИБКА] {error['file']}: {error['error']}")

            if input('\nСохранить JSON-отчёт? [y/N]: ').strip().lower() in {'y', 'yes'}:
                output = input('Имя файла [report.json]: ').strip() or 'report.json'
                output_path = Path(output).expanduser()

                if not output_path.is_absolute():
                    output_path = project_dir / output_path
                output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

                print(f'Отчёт сохранён: {output_path}')

        except (EOFError, KeyboardInterrupt):
            print('\nВыход.')
            return

        except (ValueError, OSError, yaml.YAMLError) as exc:
            print(f'Ошибка: {exc}')


def main():
    parser = argparse.ArgumentParser(description='Анализатор безопасности Python-кода')

    parser.add_argument('target', nargs='?', help='файл Python или папка; без пути откроется меню')
    parser.add_argument('--rules', default=str(Path(__file__).with_name('rules.yaml')), help='файл правил YAML')
    parser.add_argument('--output', help='путь для сохранения JSON-отчёта')

    args = parser.parse_args()
    try:
        if args.target is None:
            interactive(args.rules)
            return

        report = analyze(args.target, load_rules(args.rules))
        output = json.dumps(report, ensure_ascii=False, indent=2) + '\n'

        if args.output:
            Path(args.output).write_text(output, encoding='utf-8')
        else:
            print(output, end='')

    except (ValueError, OSError, yaml.YAMLError) as exc:
        parser.exit(2, f'Ошибка: {exc}\n')


if __name__ == '__main__':
    main()

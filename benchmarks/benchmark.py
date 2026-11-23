"""Evaluate labeled fixtures and measure wall-clock throughput."""

import argparse
import json
from pathlib import Path
from time import perf_counter

try:
    from prototype import analyzer
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import analyzer


def evaluate(root, rules_path):
    root = Path(root)
    labels = json.loads((root / 'labels.json').read_text(encoding='utf-8'))
    rules = analyzer.load_rules(rules_path)

    start = perf_counter()
    report = analyzer.analyze(root, rules)
    seconds = perf_counter() - start

    expected = {(entry['file'], entry['line'], entry['rule_id']) for entry in labels['vulnerable']}
    labeled_files = {entry[0] for entry in expected} | set(labels['safe'])
    existing_files = {path.relative_to(root).as_posix() for path in root.rglob('*.py')}
    missing = labeled_files - existing_files
    if missing:
        raise ValueError(f'Размеченные файлы отсутствуют: {sorted(missing)}')
    if report['summary']['files_scanned'] != len(existing_files):
        raise ValueError('Часть файлов датасета не была просканирована')
    found = {(entry['file'], entry['line'], entry['rule_id']) for entry in report['findings']}
    tp = len(expected & found)
    fp = len(found - expected)
    fn = len(expected - found)
    safe_files = set(labels['safe'])
    error_files = {entry['file'] for entry in report['errors']}
    tn = len(safe_files - {item[0] for item in found} - error_files)
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0

    return {'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
            'precision': precision, 'recall': recall,
            'f1': 2 * precision * recall / (precision + recall) if precision + recall else 0,
            'seconds': seconds, 'files_scanned': report['summary']['files_scanned'],
            'errors': report['summary']['errors'], 'error_files': report['errors'],
            'unit': {'TP': 'finding', 'FP': 'finding', 'FN': 'finding', 'TN': 'safe_file'},
            'rules_checked': len(rules), 'findings': len(found),
            'files_per_second': report['summary']['files_scanned'] / seconds if seconds else 0,
            'false_positives': sorted(found - expected), 'false_negatives': sorted(expected - found)}


def main():
    parser = argparse.ArgumentParser()
    here = Path(__file__).resolve().parents[1]
    parser.add_argument('--fixtures', default=str(here / 'tests' / 'fixtures'))
    parser.add_argument('--rules', default=str(here / 'rules.yaml'))
    args = parser.parse_args()

    print(json.dumps(evaluate(args.fixtures, args.rules), indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()

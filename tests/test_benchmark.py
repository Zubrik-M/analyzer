import unittest
import json
import tempfile
from pathlib import Path
from prototype.benchmarks.benchmark import evaluate


class BenchmarkTests(unittest.TestCase):
    def test_labeled_dataset(self):
        root = Path(__file__).resolve().parent / 'fixtures'
        result = evaluate(root, root.parents[1] / 'rules.yaml')
        self.assertEqual((result['TP'], result['FP'], result['TN'], result['FN']), (5, 0, 5, 0))
        self.assertEqual((result['precision'], result['recall'], result['f1']), (1, 1, 1))

    def test_extended_dataset_covers_all_rules(self):
        project = Path(__file__).resolve().parents[1]
        root = project / 'benchmarks' / 'dataset'
        result = evaluate(root, project / 'rules.yaml')
        labels = json.loads((root / 'labels.json').read_text(encoding='utf-8'))
        self.assertEqual(len(labels['vulnerable']), 22)
        self.assertEqual(result['files_scanned'], 30)
        self.assertEqual((result['TP'], result['FP'], result['TN'], result['FN'], result['errors']),
                         (22, 0, 8, 0, 0))

    def test_reports_parse_errors_and_missing_labels(self):
        rules = Path(__file__).resolve().parents[1] / 'rules.yaml'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'bad.py').write_text('def broken(:')
            labels = {'vulnerable': [], 'safe': ['bad.py']}
            (root / 'labels.json').write_text(json.dumps(labels))
            result = evaluate(root, rules)
            self.assertEqual(result['errors'], 1)
            self.assertEqual(result['TN'], 0)
            self.assertEqual(result['error_files'][0]['file'], 'bad.py')
            labels['safe'] = ['missing.py']
            (root / 'labels.json').write_text(json.dumps(labels))
            with self.assertRaises(ValueError):
                evaluate(root, rules)

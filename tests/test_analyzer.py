"""Behavior checks for the demonstrator's public analysis functions."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from prototype import analyzer
from prototype.scanner.engine import PREDICATE_CHECKS
from prototype.scanner.rules import PREDICATES


ROOT = Path(__file__).resolve().parents[1]


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.rules = analyzer.load_rules(ROOT / "rules.yaml")

    def test_every_supported_predicate_has_a_checker(self):
        self.assertEqual(set(PREDICATE_CHECKS), PREDICATES)

    def test_known_examples_and_stable_order(self):
        report = analyzer.analyze(ROOT / "examples", self.rules)
        self.assertEqual(report["summary"], {"files_scanned": 2, "findings": 3, "errors": 0})
        self.assertEqual(
            [(item["file"], item["line"], item["rule_id"]) for item in report["findings"]],
            [("vulnerable.py", 4, "PY-SECRET-001"),
             ("vulnerable.py", 7, "PY-CMD-001"),
             ("vulnerable.py", 8, "PY-DESER-001")],
        )
        self.assertEqual(report, json.loads((ROOT / "example_report.json").read_text(encoding="utf-8")))

    def test_interactive_launch_from_another_directory(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / 'report.json'
            result = subprocess.run(
                [sys.executable, str(ROOT / 'analyzer.py')],
                input=f'\ny\n{output}\n0\n', text=True, capture_output=True,
                cwd=name, check=True,
            )
            self.assertIn('Проверено файлов: 2 | предупреждений: 3 | ошибок: 0', result.stdout)
            self.assertIn('[ВЫСОКИЙ]', result.stdout)
            self.assertIn('Сохранить JSON-отчёт? [y/N]', result.stdout)
            self.assertEqual(json.loads(output.read_text(encoding='utf-8'))['summary']['findings'], 3)

    def test_skips_service_directories_and_continues_after_syntax_error(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "good.py").write_text('password = "example"\n', encoding="utf-8")
            (root / "broken.py").write_text("def bad(:\n", encoding="utf-8")
            for directory in analyzer.EXCLUDED_DIRECTORIES:
                hidden = root / directory
                hidden.mkdir()
                (hidden / "ignored.py").write_text('password = "hidden"\n', encoding="utf-8")
            report = analyzer.analyze(root, self.rules)
            self.assertEqual(report["summary"], {"files_scanned": 2, "findings": 1, "errors": 1})
            self.assertEqual(report["findings"][0]["file"], "good.py")
            self.assertEqual(report["errors"][0]["file"], "broken.py")
            self.assertEqual(report, analyzer.analyze(root, self.rules))

    def test_source_is_parsed_without_execution(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            marker = root / "executed"
            source = root / "sample.py"
            source.write_text(f'from pathlib import Path\nPath({str(marker)!r}).touch()\n', encoding="utf-8")
            report = analyzer.analyze(source, self.rules)
            self.assertEqual(report["summary"], {"files_scanned": 1, "findings": 0, "errors": 0})
            self.assertFalse(marker.exists())

    def test_rejects_bad_rule_before_scan(self):
        cases = [
            "severity: urgent",
            "match: {kind: call, predicate: string_literal, function: f}",
            "match: {kind: [call], predicate: any_call, function: f}",
            "match: {kind: call, predicate: any_call, function: f, skip_if_tainted_argument: true}",
        ]
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "rules.yaml"
            for replacement in cases:
                with self.subTest(replacement=replacement):
                    content = (
                        "rules:\n"
                        "  - id: TEST-1\n"
                        "    name: Test\n"
                        "    cwe: CWE-78\n"
                        "    severity: high\n"
                        "    description: Test rule\n"
                        "    recommendation: Review\n"
                        "    match: {kind: call, predicate: any_call, function: f}\n"
                    )
                    target = "severity: high" if replacement.startswith("severity") else "match: {kind: call, predicate: any_call, function: f}"
                    path.write_text(content.replace(target, replacement), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        analyzer.load_rules(path)

    def test_accepts_documented_severity_names(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "rules.yaml"
            path.write_text(
                "rules:\n"
                "  - id: TEST-1\n"
                "    name: Test\n"
                "    cwe: CWE-78\n"
                "    severity: High\n"
                "    description: Test rule\n"
                "    recommendation: Review\n"
                "    match: {kind: call, predicate: any_call, function: f}\n",
                encoding="utf-8",
            )
            self.assertEqual(analyzer.load_rules(path)[0]["severity"], "high")


if __name__ == "__main__":
    unittest.main()

"""Behavior tests for data flow and contextual rules."""
import tempfile
import unittest
from pathlib import Path
from prototype import analyzer

RULES = analyzer.load_rules(Path(__file__).resolve().parents[1] / 'rules.yaml')


def scan(source):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'case.py'
        path.write_text(source, encoding='utf-8')
        return analyzer.analyze(path, RULES)


class FlowTests(unittest.TestCase):
    def test_keyword_sinks_and_starred_kwargs(self):
        cases = [
            ('cursor.execute(input(), **opts)', 'PY-SQL-001'),
            ('cursor.execute(operation=input())', 'PY-SQL-001'),
            ('open(file=input())', 'PY-PATH-001'),
            ('eval(source=input())', 'PY-CODE-001'),
            ('import subprocess\nsubprocess.run(args=input(), shell=True)', 'PY-CMD-003'),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertIn(expected, [item['rule_id'] for item in scan(source)['findings']])

    def test_shadowing_chained_calls_and_relative_imports(self):
        self.assertEqual(scan('import os\nos = Fake()\nos.system(input())')['findings'], [])
        self.assertEqual(scan('import subprocess\ndef f(subprocess):\n subprocess.run(input(), shell=True)')['findings'], [])
        self.assertIn('PY-SQL-001', [f['rule_id'] for f in scan('conn.cursor().execute(f"SELECT {input()}")')['findings']])
        self.assertIn('PY-DEBUG-002', [f['rule_id'] for f in scan('create_app().run(debug=True)')['findings']])
        self.assertEqual(scan('from . import os\nos.system(input())')['findings'], [])

    def test_literal_attributes_methods_and_multiline_crypto(self):
        cases = [
            ('password = "abcd" + "efgh"', 'PY-SECRET-001'),
            ('class C:\n def run(self, value):\n  os.system(value)\n def start(self):\n  self.run(input())', 'PY-CMD-002'),
            ('self.password = "longsecret"', 'PY-SECRET-001'),
            ('app.config["DEBUG"] = True', 'PY-DEBUG-001'),
            ('password_hash = hashlib.md5(\n password\n)', 'PY-CRYPTO-001'),
            ('password_hash = hashlib.new("md5", password)', 'PY-CRYPTO-001'),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertIn(expected, [item['rule_id'] for item in scan(source)['findings']])
        self.assertNotIn('PY-CRYPTO-001', [f['rule_id'] for f in scan('checksum = hashlib.md5(data) # password')['findings']])

    def test_branch_functions_exception_prefix_and_annotation(self):
        cases = [
            'import os\nif flag:\n def run(x): os.system(x)\nelse:\n def run(x): os.system(x)\nrun(input())',
            'import os\ntry:\n command = input()\n may_fail()\nexcept ValueError:\n os.system(command)',
            'import os\ncommand = input()\ncommand: str\nos.system(command)',
            'import os\na, *b = input(), []\nos.system(a)',
            'import subprocess\nsubprocess.getstatusoutput(input())',
        ]
        for source in cases:
            with self.subTest(source=source):
                self.assertTrue(any(item['rule_id'].startswith('PY-CMD-')
                                    for item in scan(source)['findings']))

    def test_flask_import_source(self):
        source = 'from flask import request\nimport os\nos.system(request.args.get("cmd"))'
        self.assertIn('PY-CMD-002', [f['rule_id'] for f in scan(source)['findings']])

    def test_walrus_assignment_in_condition(self):
        vulnerable = 'import os\nif (command := input()):\n os.system(command)'
        safe = 'import os\nif (command := "ls"):\n os.system(command)'
        self.assertEqual([item['rule_id'] for item in scan(vulnerable)['findings']], ['PY-CMD-002'])
        self.assertEqual(scan(safe)['findings'], [])

    def test_keyword_only_and_collected_arguments(self):
        cases = [
            'import os\ndef run(*, command):\n os.system(command)\nrun(command=input())',
            'import os\ndef run(*commands):\n os.system(commands[0])\nrun(input())',
            'import os\ndef run(**options):\n os.system(options["command"])\nrun(command=input())',
        ]
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual([item['rule_id'] for item in scan(source)['findings']], ['PY-CMD-002'])

    def test_reassigned_function_is_not_analyzed_as_old_function(self):
        source = ('import os\ndef run(value):\n os.system(value)\n'
                  'run = lambda value: None\nrun(input())')
        self.assertEqual(scan(source)['findings'], [])

    def test_import_replaces_previous_function_binding(self):
        source = ('import os\ndef run(value):\n os.system(value)\n'
                  'from math import sqrt as run\nrun(input())')
        self.assertEqual(scan(source)['findings'], [])

    def test_local_import_shadows_outer_value(self):
        source = ('import os\nmodule = input()\ndef run():\n'
                  ' import math as module\n os.system(module.sqrt(4))\nrun()')
        self.assertEqual(scan(source)['findings'], [])

    def test_function_binding_after_branches(self):
        prefix = 'import os\ndef run(value):\n os.system(value)\n'
        possible = prefix + 'if flag:\n run = lambda value: None\nrun(input())'
        replaced = prefix + ('if flag:\n run = lambda value: None\n'
                             'else:\n run = lambda value: None\nrun(input())')
        self.assertEqual([item['rule_id'] for item in scan(possible)['findings']], ['PY-CMD-002'])
        self.assertEqual(scan(replaced)['findings'], [])

    def test_comprehension_scope_and_flow(self):
        vulnerable = 'import os\n[os.system(command) for command in [input()]]'
        safe = 'import os\n[os.system(command) for command in ["ls"]]'
        self.assertEqual([item['rule_id'] for item in scan(vulnerable)['findings']], ['PY-CMD-002'])
        self.assertEqual(scan(safe)['findings'], [])

    def test_match_capture_flow(self):
        vulnerable = 'import os\nmatch input():\n case command:\n  os.system(command)'
        safe = 'import os\nmatch "ls":\n case command:\n  os.system(command)'
        self.assertEqual([item['rule_id'] for item in scan(vulnerable)['findings']], ['PY-CMD-002'])
        self.assertEqual(scan(safe)['findings'], [])

    def test_class_methods_are_scanned(self):
        source = 'import os\nclass Handler:\n def run(self):\n  os.system(input())'
        self.assertEqual(
            [(item['rule_id'], item['line']) for item in scan(source)['findings']],
            [('PY-CMD-002', 4)],
        )

    def test_required_command_paths(self):
        cases = [
            ('import os\nos.system(input())', 2),
            ('import os\na=input()\nos.system(a)', 3),
            ('import os\na=input()\nb=a\nc=b\nos.system(c)', 5),
            ('import os\na=input()\nc=f"echo {a}"\nos.system(c)', 4),
            ('import os\na=input()\nc="echo {}".format(a)\nos.system(c)', 4),
            ('import os\ndef run_command(value):\n os.system(value)\na=input()\nrun_command(a)', 3),
            ('import os\ndef get_command():\n return input()\na=get_command()\nos.system(a)', 5),
            ('import os\na=input()\nif a: c=a\nelse: c="safe"\nos.system(c)', 5),
        ]
        for source, line in cases:
            with self.subTest(source=source):
                findings = scan(source)['findings']
                self.assertEqual([(f['rule_id'], f['severity'], f['line']) for f in findings], [('PY-CMD-002', 'high', line)])
                self.assertEqual(findings[0]['taint']['source'], 'input')

    def test_safe_command_paths(self):
        cases = [
            'import subprocess\nsubprocess.run(["ls", "-la"], shell=False)',
            'import os, shlex\na=input()\nc=shlex.quote(a)\nos.system("echo " + c)',
            'import os\na=input()\na="safe"\nos.system(a)',
            'import os\ndef first():\n x=input()\ndef second():\n os.system(x)',
            'from subprocess import run\ndef run(x, shell=False): pass\nrun(input(),shell=True)',
            'from subprocess import run\ndef f():\n run(input(), shell=True)\n run=lambda x, shell: None',
        ]
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(scan(source)['findings'], [])

    def test_aliases_and_nested_calls(self):
        forms = ['import subprocess\nsubprocess.run', 'import subprocess as sp\nsp.run',
                 'from subprocess import run\nrun', 'from subprocess import run as execute\nexecute']
        for prefix in forms:
            with self.subTest(prefix=prefix):
                source = prefix + '(input(), shell=True)'
                found = scan(source)['findings']
                self.assertEqual([(f['rule_id'], f['line']) for f in found], [('PY-CMD-003', 2)])

    def test_command_deduplication_does_not_depend_on_rule_id(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rules_file = root / 'rules.yaml'
            source_file = root / 'case.py'
            original = Path(__file__).resolve().parents[1] / 'rules.yaml'
            rules_file.write_text(original.read_text(encoding='utf-8').replace(
                'id: PY-CMD-001', 'id: TEST-CMD-001'), encoding='utf-8')
            source_file.write_text('import subprocess\nsubprocess.run(input(), shell=True)', encoding='utf-8')

            report = analyzer.analyze(source_file, analyzer.load_rules(rules_file))
            self.assertEqual([item['rule_id'] for item in report['findings']], ['PY-CMD-003'])

    def test_sql_and_file_context(self):
        cases = [
            ('x=input()\nquery=f"SELECT {x}"\ncursor.execute(query)', 'PY-SQL-001'),
            ('x=input()\ncursor.executemany("SELECT " + x, [])', 'PY-SQL-002'),
            ('x=input()\nopen(x)', 'PY-PATH-001'),
            ('import os\nx=input()\nopen(os.path.join("/base",x))', 'PY-PATH-001'),
        ]
        for source, rule_id in cases:
            with self.subTest(source=source):
                self.assertIn(rule_id, [x['rule_id'] for x in scan(source)['findings']])
        for source in ('x=input()\ncursor.execute("SELECT ?", (x,))',
                       'open("/fixed/file.txt")'):
            self.assertEqual(scan(source)['findings'], [])

    def test_configurable_sources_and_context_specific_sanitizer(self):
        sources = [
            'x=request.args.get("cmd")\nos.system(x)',
            'x=request.form["cmd"]\nos.system(x)',
            'x=request.json\nos.system(x)',
            'x=request.values["cmd"]\nos.system(x)',
            'import os\nx=os.environ.get("CMD")\nos.system(x)',
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual([f['rule_id'] for f in scan(source)['findings']], ['PY-CMD-002'])
        # Shell quoting is not a SQL sanitizer.
        source = 'import shlex\nx=input()\nq=shlex.quote(x)\ncursor.execute("SELECT " + q)'
        self.assertEqual([f['rule_id'] for f in scan(source)['findings']], ['PY-SQL-001'])

    def test_loop_and_try_joins(self):
        sources = [
            'import os\nx="safe"\nfor item in [input()]:\n x=item\nos.system(x)',
            'import os\nx="safe"\ntry:\n x=input()\nexcept ValueError:\n pass\nos.system(x)',
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual([f['rule_id'] for f in scan(source)['findings']], ['PY-CMD-002'])

    def test_literal_allowlist_only_narrows_true_branch(self):
        safe = 'import os\nx=input()\nif x in {"ls", "pwd"}:\n os.system(x)'
        unsafe = 'import os\nx=input()\nif x in {"ls", "pwd"}:\n pass\nelse:\n os.system(x)'
        self.assertEqual(scan(safe)['findings'], [])
        self.assertEqual([f['rule_id'] for f in scan(unsafe)['findings']], ['PY-CMD-002'])

    def test_rule_categories_positive_and_safe(self):
        cases = [
            ('os.popen(input())', 'PY-CMD-004', 'os.popen("ls")'),
            ('api_token="longsecretvalue"', 'PY-SECRET-002', 'api_token="placeholder"'),
            ('pickle.load(stream)', 'PY-DESER-002', 'json.load(stream)'),
            ('yaml.load(data)', 'PY-DESER-003', 'yaml.load(data, Loader=yaml.SafeLoader)'),
            ('eval(input())', 'PY-CODE-001', 'eval("1+2")'),
            ('exec(input())', 'PY-CODE-002', 'exec("x=1")'),
            ('password_hash=hashlib.md5(password)', 'PY-CRYPTO-001', 'checksum=hashlib.md5(data)'),
            ('signature=hashlib.sha1(data).hexdigest()', 'PY-CRYPTO-002', 'checksum=hashlib.sha1(data).hexdigest()'),
            ('token=random.choice(chars)', 'PY-RANDOM-001', 'dice=random.choice(range(6))'),
            ('requests.get(url, verify=False)', 'PY-TLS-001', 'requests.get(url, verify=True)'),
            ('ssl._create_unverified_context()', 'PY-TLS-002', 'ssl.create_default_context()'),
            ('DEBUG=True', 'PY-DEBUG-001', 'DEBUG=False'),
            ('app.run(debug=True)', 'PY-DEBUG-002', 'app.run(debug=False)'),
            ('tempfile.mktemp()', 'PY-TEMP-001', 'tempfile.NamedTemporaryFile()'),
        ]
        for bad, expected, good in cases:
            with self.subTest(rule=expected):
                self.assertIn(expected, [f['rule_id'] for f in scan(bad)['findings']])
                self.assertNotIn(expected, [f['rule_id'] for f in scan(good)['findings']])

    def test_syntax_error_and_multiple_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'bad.py').write_text('def x(:')
            (root / 'good.py').write_text('import os\nos.system(input())\neval(input())')
            result = analyzer.analyze(root, RULES)
            self.assertEqual(result['summary'], {'files_scanned': 2, 'findings': 2, 'errors': 1})


if __name__ == '__main__':
    unittest.main()

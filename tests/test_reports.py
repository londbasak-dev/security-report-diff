import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from security_report_diff.reports import ReportError, compare, load_report, parse_report, normalize_path


def sarif(results):
    return {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'SyntheticScanner'}}, 'results': results}]}


def finding(rule='R1', path='src/main.py', level='warning', fingerprint=None):
    item = {'ruleId': rule, 'level': level, 'message': {'text': 'SECRET_DO_NOT_OUTPUT'},
            'locations': [{'physicalLocation': {'artifactLocation': {'uri': path}, 'region': {'startLine': 10}}}]}
    if fingerprint:
        item['partialFingerprints'] = {'primaryLocationLineHash': fingerprint}
    return item


class ReportTests(unittest.TestCase):
    def test_new_resolved_severity(self):
        before = parse_report(sarif([finding(), finding('OLD')]))
        after = parse_report(sarif([finding(level='error'), finding('NEW')]))
        result = compare(before, after)
        self.assertEqual(len(result['new']), 1)
        self.assertEqual(len(result['resolved']), 1)
        self.assertEqual(result['severity_changed'][0]['after'], 'error')

    def test_no_message_properties_or_raw_fingerprint(self):
        item = finding(fingerprint='SECRET_FP')
        item['properties'] = {'password': 'SECRET_PROPERTY'}
        output = json.dumps(compare([], parse_report(sarif([item]))))
        self.assertNotIn('SECRET', output)
        self.assertNotIn('message', output)

    def test_duplicate_multiset(self):
        result = compare(parse_report(sarif([finding(), finding()])), parse_report(sarif([finding()])))
        self.assertEqual(len(result['resolved']), 1)
        self.assertEqual(result['unchanged_count'], 1)

    def test_fingerprint_survives_line_change(self):
        first = finding(fingerprint='abc')
        second = finding(fingerprint='abc')
        second['locations'][0]['physicalLocation']['region']['startLine'] = 99
        result = compare(parse_report(sarif([first])), parse_report(sarif([second])))
        self.assertEqual(result['unchanged_count'], 1)

    def test_fingerprint_does_not_hide_path_change(self):
        result = compare(parse_report(sarif([finding(fingerprint='abc')])), parse_report(sarif([finding(path='src/new.py', fingerprint='abc')])))
        self.assertEqual(len(result['new']), 1)
        self.assertEqual(len(result['resolved']), 1)

    def test_same_line_different_fingerprint_distinct(self):
        result = compare(parse_report(sarif([finding(fingerprint='a')])), parse_report(sarif([finding(fingerprint='b')])))
        self.assertEqual(len(result['new']), 1)

    def test_relative_paths_normalized(self):
        self.assertEqual(normalize_path('src\\a\\..\\b.py'), 'src/b.py')
        self.assertEqual(normalize_path('./src/%62.py'), 'src/b.py')

    def test_external_paths_masked(self):
        for path in ('C:\\Users\\private\\file.py', '/home/private/file.py', '../../private.py', 'https://example.invalid/private?token=secret', 'file:///home/private/a.py'):
            with self.subTest(path=path):
                self.assertTrue(normalize_path(path).startswith('[external:'))
                self.assertNotIn('private', normalize_path(path))

    def test_repo_root_makes_absolute_relative(self):
        self.assertEqual(normalize_path('/repo/src/a.py', '/repo'), 'src/a.py')
        self.assertEqual(normalize_path('file:///C:/repo/src/a.py', 'C:/repo'), 'src/a.py')

    def test_windows_query_and_fragment_are_masked(self):
        for path in ('C:/repo/src/a.py?token=SYNTHETIC_QUERY', 'C:\\repo\\src\\a.py#SYNTHETIC_FRAGMENT'):
            with self.subTest(path=path):
                normalized = normalize_path(path, 'C:/repo')
                self.assertTrue(normalized.startswith('[external:'))
                self.assertNotIn('SYNTHETIC', normalized)

    def test_invalid_reports(self):
        for report in ({}, {'version': '2.0.0', 'runs': []}, sarif([{'message': {'text': 'no rule'}}]), sarif([finding(level='critical')])):
            with self.subTest(report=report), self.assertRaises(ReportError):
                parse_report(report)

    def test_malformed_shapes_controlled_error(self):
        for value in (None, [], {'version': '2.1.0', 'runs': None}, sarif([{'ruleId': 'R', 'level': []}]), sarif([{'ruleId': 'R', 'locations': [None]}]), sarif([{'ruleId': 'R', 'partialFingerprints': []}])):
            with self.subTest(value=value), self.assertRaises(ReportError):
                parse_report(value)

    def test_invalid_json_and_size_limit(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'sample.sarif'
            path.write_bytes(b'{"password":"DO_NOT_PRINT"')
            with self.assertRaises(ReportError) as error:
                load_report(path)
            self.assertNotIn('DO_NOT_PRINT', str(error.exception))
            with path.open('wb') as stream:
                stream.truncate(20 * 1024 * 1024 + 1)
            with self.assertRaises(ReportError):
                load_report(path)

    def test_rule_default_severity(self):
        item = finding()
        del item['level']
        report = sarif([item])
        report['runs'][0]['tool']['driver']['rules'] = [{'id': 'R1', 'defaultConfiguration': {'level': 'error'}}]
        self.assertEqual(parse_report(report)[0]['level'], 'error')
        item['kind'] = 'pass'
        self.assertEqual(parse_report(report)[0]['level'], 'none')
        item['level'] = 'warning'
        with self.assertRaises(ReportError):
            parse_report(report)

    def test_stable_order(self):
        first = compare([], parse_report(sarif([finding('Z'), finding('A')])))
        second = compare([], parse_report(sarif([finding('A'), finding('Z')])))
        self.assertEqual(first, second)

    def test_cli_json(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'sample.sarif'
            path.write_text(json.dumps(sarif([finding()])), encoding='utf-8')
            result = subprocess.run([sys.executable, '-m', 'security_report_diff', str(path), str(path), '--format', 'json'], capture_output=True)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout)['unchanged_count'], 1)
            path.write_text('{"private":"SYNTHETIC_INVALID_JSON"', encoding='utf-8')
            result = subprocess.run([sys.executable, '-m', 'security_report_diff', str(path), str(path)], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b'SYNTHETIC_INVALID_JSON', result.stderr)

    def test_argument_errors_do_not_echo_paths(self):
        result = subprocess.run([sys.executable, '-m', 'security_report_diff', 'before.synthetic', 'after.synthetic', 'C:/SyntheticPrivate/ExtraFile.xml'], capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b'SyntheticPrivate', result.stderr)
        self.assertNotIn(b'ExtraFile', result.stderr)


if __name__ == '__main__':
    unittest.main()

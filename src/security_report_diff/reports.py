"""Allowlisted SARIF parsing, safe location normalization and multiset matching."""
import hashlib
import json
import ntpath
import posixpath
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote, urlsplit

MAX_REPORT = 20 * 1024 * 1024
LEVELS = {'none', 'note', 'warning', 'error'}
KINDS = {'fail', 'pass', 'open', 'informational', 'notApplicable', 'review'}


class ReportError(ValueError):
    """A report is invalid or outside this tool's supported SARIF subset."""


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()[:24]


def normalize_path(uri, repo_root=None):
    if not isinstance(uri, str) or len(uri) > 8192:
        raise ReportError('Invalid artifact URI.')
    original = uri
    uri = unquote(uri).replace('\\', '/')
    windows = bool(re.match(r'^/?[A-Za-z]:/', uri))
    if windows and ('?' in uri or '#' in uri):
        # Drive paths bypass URL parsing so that the drive is not mistaken for
        # a scheme. Still mask URL suffixes before making the path relative.
        return '[external:' + digest(original) + ']'
    parsed = urlsplit(uri) if not windows else None
    if parsed and parsed.scheme:
        if parsed.scheme != 'file' or parsed.netloc:
            return '[external:' + digest(original) + ']'
        uri = parsed.path
        windows = bool(re.match(r'^/[A-Za-z]:/', uri))
    elif parsed and (parsed.query or parsed.fragment):
        return '[external:' + digest(original) + ']'
    if windows:
        uri = uri.lstrip('/')
    absolute = windows or uri.startswith('/')
    normalized = posixpath.normpath(uri)
    if absolute and repo_root:
        root = str(repo_root).replace('\\', '/').rstrip('/')
        if windows and re.match(r'^[A-Za-z]:/', root):
            relative = ntpath.relpath(normalized, root).replace('\\', '/') if ntpath.splitdrive(normalized)[0].lower() == ntpath.splitdrive(root)[0].lower() else '../outside'
        elif not windows and root.startswith('/'):
            relative = posixpath.relpath(normalized, posixpath.normpath(root))
        else:
            relative = '../outside'
        if relative != '..' and not relative.startswith('../'):
            normalized, absolute = relative, False
    if absolute or normalized == '..' or normalized.startswith('../') or '\x00' in normalized or any(ord(c) < 32 for c in normalized):
        return '[external:' + digest(original) + ']'
    return normalized


def _dict(value):
    if not isinstance(value, dict):
        raise ReportError('Expected a JSON object in the SARIF structure.')
    return value


def _list(value):
    if not isinstance(value, list):
        raise ReportError('Expected a JSON array in the SARIF structure.')
    return value


def _rule(value):
    if not isinstance(value, str) or not value or len(value) > 256 or any(ord(c) < 32 for c in value):
        raise ReportError('Missing or invalid rule identifier.')
    return value


def parse_report(report, repo_root=None):
    report = _dict(report)
    if report.get('version') != '2.1.0' or 'runs' not in report:
        raise ReportError('Expected SARIF version 2.1.0 with runs.')
    findings = []
    for run in _list(report['runs']):
        run = _dict(run)
        driver = _dict(_dict(run.get('tool', {})).get('driver', {}))
        scanner = digest(str(driver.get('name', 'unknown')))
        defaults = {}
        rules = _list(driver.get('rules', []))
        for rule in rules:
            rule = _dict(rule)
            defaults[_rule(rule.get('id'))] = _dict(rule.get('defaultConfiguration', {})).get('level', 'warning')
        for item in _list(run.get('results', [])):
            item = _dict(item)
            rule_id = item.get('ruleId')
            if rule_id is None and isinstance(item.get('ruleIndex'), int) and not isinstance(item['ruleIndex'], bool) and 0 <= item['ruleIndex'] < len(rules):
                rule_id = rules[item['ruleIndex']].get('id')
            rule_id = _rule(rule_id)
            kind = item.get('kind', 'fail')
            if not isinstance(kind, str) or kind not in KINDS:
                raise ReportError('Unsupported SARIF result kind.')
            level = item.get('level', defaults.get(rule_id, 'warning') if kind == 'fail' else 'none')
            if not isinstance(level, str) or level not in LEVELS:
                raise ReportError('Unsupported SARIF level.')
            if kind != 'fail' and level != 'none':
                raise ReportError('Non-fail SARIF results must have level none.')
            locations = _list(item.get('locations', []))
            path, line, column = '[no-location]', 0, 0
            if locations:
                physical = _dict(_dict(locations[0]).get('physicalLocation', {}))
                artifact = _dict(physical.get('artifactLocation', {}))
                if 'uri' in artifact:
                    path = normalize_path(artifact['uri'], repo_root)
                region = _dict(physical.get('region', {}))
                line, column = region.get('startLine', 0), region.get('startColumn', 0)
                if any(not isinstance(v, int) or isinstance(v, bool) or v < 0 for v in (line, column)):
                    raise ReportError('Invalid location region.')
            fingerprint = None
            for field in ('fingerprints', 'partialFingerprints'):
                values = _dict(item.get(field, {}))
                for name in sorted(values):
                    value = values[name]
                    if not isinstance(value, str):
                        raise ReportError('Invalid fingerprint value.')
                if values:
                    # Hash sorted names and values, never emit scanner fingerprint text.
                    fingerprint = digest(json.dumps(values, sort_keys=True, separators=(',', ':')))
                    break
            findings.append({'scanner': scanner, 'rule_id': rule_id, 'path': path,
                             'line': line, 'column': column, 'fingerprint': fingerprint, 'level': level})
            if len(findings) > 100000:
                raise ReportError('Too many findings.')
    return findings


def load_report(path, repo_root=None):
    try:
        with Path(path).open('rb') as stream:
            data = stream.read(MAX_REPORT + 1)
        if len(data) > MAX_REPORT:
            raise ReportError('Report exceeds the 20 MiB limit.')
        return parse_report(json.loads(data), repo_root)
    except ReportError:
        raise
    except (OSError, ValueError, RecursionError, TypeError):
        raise ReportError('Cannot read valid SARIF JSON input.') from None


def compare(before, after):
    def identity(item):
        location = ('fingerprint', item['fingerprint']) if item['fingerprint'] else ('region', item['line'], item['column'])
        return (item['scanner'], item['rule_id'], item['path'], location)
    old, new = defaultdict(list), defaultdict(list)
    for item in before:
        old[identity(item)].append(item)
    for item in after:
        new[identity(item)].append(item)
    result = {'new': [], 'resolved': [], 'severity_changed': [], 'unchanged_count': 0}
    for key in sorted(old.keys() | new.keys(), key=repr):
        old_items = sorted(old[key], key=lambda item: (item['level'], item['line'], item['column']))
        new_items = sorted(new[key], key=lambda item: (item['level'], item['line'], item['column']))
        # Match identical severity first so duplicate reordering cannot invent changes.
        for level in sorted(LEVELS):
            matching_old = [item for item in old_items if item['level'] == level]
            matching_new = [item for item in new_items if item['level'] == level]
            count = min(len(matching_old), len(matching_new))
            result['unchanged_count'] += count
            for item in matching_old[:count]:
                old_items.remove(item)
            for item in matching_new[:count]:
                new_items.remove(item)
        paired = min(len(old_items), len(new_items))
        for first, second in zip(old_items[:paired], new_items[:paired]):
            result['severity_changed'].append({'finding': {k: v for k, v in second.items() if k != 'level'}, 'before': first['level'], 'after': second['level']})
        result['resolved'].extend(old_items[paired:])
        result['new'].extend(new_items[paired:])
    return result

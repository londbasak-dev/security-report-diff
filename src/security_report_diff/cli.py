import argparse
import json
import sys
from .reports import ReportError, compare, load_report


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'Error: invalid command arguments; use --help.\n')


def main(argv=None):
    parser = SafeArgumentParser(description='Compare SARIF 2.1.0 findings without outputting messages or properties.')
    parser.add_argument('before')
    parser.add_argument('after')
    parser.add_argument('--repo-root', help='Repository root for normalizing absolute artifact locations')
    parser.add_argument('--format', choices=('text', 'json'), default='text')
    args = parser.parse_args(argv)
    try:
        result = compare(load_report(args.before, args.repo_root), load_report(args.after, args.repo_root))
    except ReportError as error:
        print(f'Error: {error}', file=sys.stderr)
        return 2
    if args.format == 'json':
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True))
    else:
        print(f"New: {len(result['new'])}; resolved: {len(result['resolved'])}; severity changes: {len(result['severity_changed'])}; unchanged: {result['unchanged_count']}")
        for kind in ('new', 'resolved', 'severity_changed'):
            for item in result[kind]:
                print(f'{kind}: {json.dumps(item, sort_keys=True, ensure_ascii=True)}')
    return 0

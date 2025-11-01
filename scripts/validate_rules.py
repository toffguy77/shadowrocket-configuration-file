#!/usr/bin/env python3
"""
Validate Shadowrocket-like rule lists.
Usage: python3 scripts/validate_rules.py <path>

Checks:
- UTF-8 readability
- Valid line types: comments, blank, DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN, IP-CIDR, IP-CIDR6, RULE-SET, FINAL, simple actions
- IP/CIDR correctness
- RULE-SET URL parsing
- Duplicates and simple warnings
"""
import sys
import re
import argparse
import urllib.parse
import ipaddress
from collections import Counter
try:
    import requests
except Exception:
    requests = None

DOMAIN_RE = re.compile(r"^(?:\*\.)?[A-Za-z0-9\-](?:[A-Za-z0-9\-]|\.)*[A-Za-z0-9\-]$")
LINE_LIMIT = 800

def is_comment(line):
    return line.strip().startswith('#') or line.strip().startswith('//')

def is_blank(line):
    return line.strip() == ''

def check_domain_token(tok):
    tok = tok.strip()
    if tok == '*':
        return True
    # allow wildcard prefix *.example.com
    if tok.startswith('*.'):
        return DOMAIN_RE.match(tok[2:]) is not None
    return DOMAIN_RE.match(tok) is not None

def check_ip_cidr(tok):
    try:
        # accept both ipv4/cidr and ipv6/cidr
        ipaddress.ip_network(tok, strict=False)
        return True
    except Exception:
        return False

def check_rule_set(parts):
    # expected: RULE-SET,<url>,<ACTION>[,no-resolve]
    if len(parts) < 3:
        return False, 'RULE-SET needs at least 2 commas (url,action)'
    url = parts[1].strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('http','https') or not parsed.netloc:
        return False, f'RULE-SET URL seems invalid: {url}'
    action = parts[2].strip().upper()
    if action not in ('PROXY','DIRECT','REJECT'):
        return False, f'Unknown action in RULE-SET: {action}'
    # optional flags
    if len(parts) > 3:
        for flag in parts[3:]:
            if flag.strip().lower() not in ('no-resolve',):
                return False, f'Unknown flag in RULE-SET: {flag}'
    return True, None

PATTERNS = [
    ('COMMENT', is_comment),
    ('BLANK', is_blank),
    ('DOMAIN-SUFFIX', lambda l: l.upper().startswith('DOMAIN-SUFFIX,')),
    ('DOMAIN-KEYWORD', lambda l: l.upper().startswith('DOMAIN-KEYWORD,')),
    ('DOMAIN', lambda l: l.upper().startswith('DOMAIN,')),
    ('IP-CIDR', lambda l: l.upper().startswith('IP-CIDR,')),
    ('IP-CIDR6', lambda l: l.upper().startswith('IP-CIDR6,')),
    ('RULE-SET', lambda l: l.upper().startswith('RULE-SET,')),
    ('FINAL', lambda l: l.upper().startswith('FINAL,')),
    ('SIMPLE-ACTION', lambda l: l.strip().upper() in ('PROXY','DIRECT','REJECT')),
]


def validate(path):
    errors = []
    warnings = []
    lines = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            raw_lines = f.readlines()
    except UnicodeDecodeError:
        return { 'ok': False, 'errors': ['File is not valid UTF-8 or contains invalid bytes.'] }
    except FileNotFoundError:
        return { 'ok': False, 'errors': [f'File not found: {path}'] }

    for i, raw in enumerate(raw_lines, 1):
        line = raw.rstrip('\n')
        lines.append(line)
        if len(line) > LINE_LIMIT:
            warnings.append((i, 'line over %d chars' % LINE_LIMIT))
        if line.endswith(' '):
            warnings.append((i, 'trailing space'))

        matched = False
        for name, checker in PATTERNS:
            try:
                if checker(line):
                    matched = True
                    # detailed checks
                    if name == 'DOMAIN-SUFFIX':
                        parts = line.split(',',1)
                        if len(parts) != 2 or not check_domain_token(parts[1]):
                            errors.append((i, line, 'Invalid DOMAIN-SUFFIX token'))
                    elif name == 'DOMAIN-KEYWORD':
                        parts = line.split(',',1)
                        if len(parts) != 2 or parts[1].strip() == '':
                            errors.append((i, line, 'Invalid DOMAIN-KEYWORD token'))
                    elif name == 'DOMAIN':
                        parts = line.split(',',1)
                        if len(parts) != 2 or not check_domain_token(parts[1]):
                            errors.append((i, line, 'Invalid DOMAIN token'))
                    elif name == 'IP-CIDR':
                        parts = line.split(',',1)
                        if len(parts) != 2 or not check_ip_cidr(parts[1].strip()):
                            errors.append((i, line, 'Invalid IP-CIDR'))
                    elif name == 'IP-CIDR6':
                        parts = line.split(',',1)
                        if len(parts) != 2 or not check_ip_cidr(parts[1].strip()):
                            errors.append((i, line, 'Invalid IP-CIDR6'))
                    elif name == 'RULE-SET':
                        parts = [p for p in line.split(',')]
                        ok, msg = check_rule_set(parts)
                        if not ok:
                            errors.append((i, line, msg))
                    elif name == 'FINAL':
                        parts = line.split(',',1)
                        if len(parts) != 2 or parts[1].strip().upper() not in ('DIRECT','PROXY','REJECT'):
                            errors.append((i, line, 'Invalid FINAL target, expected DIRECT/PROXY/REJECT'))
                    break
            except Exception as e:
                errors.append((i, line, f'Checker error: {e}'))
        if not matched:
            # allow lines that are like "KEY,rest..." where KEY is unknown but common (keep as warning)
            if line.strip() == '':
                continue
            if not is_comment(line):
                # consider it error if it contains a comma and unknown key
                if ',' in line:
                    key = line.split(',',1)[0].strip()
                    known = [k for k,_ in PATTERNS]
                    if key.upper() not in ('DOMAIN-SUFFIX','DOMAIN-KEYWORD','DOMAIN','IP-CIDR','IP-CIDR6','RULE-SET','FINAL'):
                        warnings.append((i, f'Unknown rule key: {key}'))
                else:
                    # lines without commas could be plain actions (handled) or unknown
                    warnings.append((i, 'Unrecognized line format'))

    # duplicates
    cnt = Counter([l for l in lines if l.strip() != '' and not l.strip().startswith('#')])
    dups = [(i, l) for l,c in cnt.items() if c > 1 for i, line in enumerate(lines,1) if line == l]
    if dups:
        for i,l in dups:
            warnings.append((i, 'Duplicate rule'))

    return {'ok': len(errors) == 0, 'errors': errors, 'warnings': warnings, 'lines': lines}


def main():
    parser = argparse.ArgumentParser(description='Validate rules file')
    parser.add_argument('path')
    parser.add_argument('--check-urls', action='store_true', help='Check RULE-SET URLs are reachable (requires requests)')
    args = parser.parse_args()
    path = args.path
    res = validate(path)
    if not res['ok'] and len(res.get('errors',[])) == 0:
        print('Validation failed early')
        sys.exit(2)
    # optional URL availability checks
    if args.check_urls:
        if requests is None:
            print('ERROR: --check-urls requested but "requests" package is not available')
            sys.exit(2)
        url_errors = []
        for ln, l in enumerate(res.get('lines', []), 1):
            if l.upper().startswith('RULE-SET,'):
                parts = [p for p in l.split(',')]
                if len(parts) >= 2:
                    url = parts[1].strip()
                    try:
                        r = requests.head(url, allow_redirects=True, timeout=10)
                        if r.status_code >= 400:
                            url_errors.append((ln, url, f'HTTP {r.status_code}'))
                    except Exception as e:
                        url_errors.append((ln, url, f'Exception: {e}'))
        if url_errors:
            print(f'ERROR: {len(url_errors)} RULE-SET URL(s) unreachable')
            for ln,url,msg in url_errors:
                print(f'{ln:4d}: {msg} -- {url}')
            sys.exit(3)
    if res['ok']:
        print(f'OK: {path} — формат в порядке, warnings: {len(res.get("warnings",[]))}')
    else:
        print(f'ERROR: {len(res.get("errors",[]))} problem(s) found:')
        for ln, txt, msg in res['errors'][:200]:
            print(f'{ln:4d}: {msg} -- {txt}')
    if res.get('warnings'):
        print('\nWarnings:')
        for ln, msg in res['warnings'][:500]:
            print(f'{ln:4d}: {msg}')
    sys.exit(0 if res['ok'] else 3)

if __name__ == '__main__':
    main()

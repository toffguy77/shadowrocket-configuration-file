#!/usr/bin/env python3
"""
Basic validation for ru_config-private.conf file.

Checks performed:
- file is UTF-8
- contains [Rule] section
- contains at least one RULE-SET line
- ensures there is a FINAL line
- basic RULE-SET URL parsing

This is intentionally lightweight. Extend as needed.
"""
import sys
import re
import urllib.parse

def main(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            s = f.read()
    except UnicodeDecodeError:
        print('ERROR: file is not valid UTF-8')
        return 2
    except FileNotFoundError:
        print(f'ERROR: file not found: {path}')
        return 2

    if '[Rule]' not in s:
        print('ERROR: missing [Rule] section')
        return 2

    rules = s.split('[Rule]',1)[1]
    lines = [l.strip() for l in rules.splitlines() if l.strip() and not l.strip().startswith('#')]
    has_ruleset = any(l.upper().startswith('RULE-SET,') for l in lines)
    if not has_ruleset:
        print('ERROR: no RULE-SET found in [Rule] section')
        return 2

    has_final = any(l.upper().startswith('FINAL,') for l in lines)
    if not has_final:
        print('ERROR: no FINAL,<target> in [Rule] section')
        return 2

    # Basic RULE-SET URL checks
    for i,l in enumerate(lines,1):
        if l.upper().startswith('RULE-SET,'):
            parts = [p.strip() for p in l.split(',')]
            if len(parts) < 3:
                print(f'ERROR: RULE-SET line malformed: {l}')
                return 2
            url = parts[1]
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in ('http','https') or not parsed.netloc:
                print(f'ERROR: RULE-SET URL invalid: {url}')
                return 2

    print('OK: config looks valid (basic checks)')
    return 0


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: validate_config.py <file>')
        sys.exit(2)
    sys.exit(main(sys.argv[1]))

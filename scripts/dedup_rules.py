#!/usr/bin/env python3
"""
Create a deduplicated copy of a rules file.
Keeps comments and blank lines. Removes duplicate non-comment rule lines, keeping first occurrence.
Usage: python3 scripts/dedup_rules.py rules/private.list > rules/private.dedup.list
"""
import sys

def dedup(path, out_path):
    seen = set()
    with open(path, 'r', encoding='utf-8') as f, open(out_path, 'w', encoding='utf-8') as o:
        for line in f:
            s = line.rstrip('\n')
            if s.strip() == '' or s.strip().startswith('#') or s.strip().startswith('//'):
                o.write(line)
                continue
            if s in seen:
                # skip duplicate
                continue
            seen.add(s)
            o.write(line)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: dedup_rules.py <infile> <outfile>')
        sys.exit(2)
    dedup(sys.argv[1], sys.argv[2])

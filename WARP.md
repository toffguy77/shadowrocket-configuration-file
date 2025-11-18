# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Overview

This repo maintains a Shadowrocket configuration (`ru_config-private.conf`) plus custom rule lists under `rules/`. The main flow:

- Source-of-truth: `rules/private.list` (routes via PROXY) and `rules/private.direct.list` (routes DIRECT).
- Derived artifacts (CI and local):
  - `rules/private.dedup.list`
  - `rules/private.dedup-direct.list`
- The Shadowrocket config `ru_config-private.conf` references external RULE-SETs and the private lists (preferably the deduped ones).

Two GitHub Actions automate validation, deduplication, and config regeneration:
- `.github/workflows/validate-and-dedup.yml` validates lists/config, produces deduped lists, and commits updates when needed.
- `.github/workflows/update-config.yml` periodically rebuilds `ru_config-private.conf` from an upstream base and injects private RULE-SETs.

## Common local commands

Prereqs: Python 3 (CI uses 3.11). For URL reachability checks, install `requests`:

```sh
python3 -m pip install --upgrade pip requests
```

Validate a single rules file (fast local check):

```sh
python3 scripts/validate_rules.py rules/private.list
python3 scripts/validate_rules.py rules/private.direct.list
```

Validate with URL reachability (requires `requests`):

```sh
python3 scripts/validate_rules.py rules/private.list --check-urls
python3 scripts/validate_rules.py rules/private.direct.list --check-urls
```

Produce deduplicated rule files:

```sh
python3 scripts/dedup_rules.py rules/private.list rules/private.dedup.list
python3 scripts/dedup_rules.py rules/private.direct.list rules/private.dedup-direct.list
```

Validate the deduplicated outputs:

```sh
python3 scripts/validate_rules.py rules/private.dedup.list --check-urls
python3 scripts/validate_rules.py rules/private.dedup-direct.list --check-urls
```

Validate the Shadowrocket config:

```sh
python3 scripts/validate_config.py ru_config-private.conf
```

Regenerate `ru_config-private.conf` from upstream base (same approach as CI):

```sh
# Fetch base
curl -o base_config.conf \
  https://raw.githubusercontent.com/amatol/shadowrocket-configuration/refs/heads/main/ru_config.conf

# Inject private RULE-SETs before the first FINAL,DIRECT
awk 'BEGIN{added=0} {
  if(!added && $0 ~ /^FINAL,DIRECT/){
    print "RULE-SET,https://raw.githubusercontent.com/toffguy77/shadowrocket-configuration-file/refs/heads/main/rules/private.list,PROXY";
    print "RULE-SET,https://raw.githubusercontent.com/toffguy77/shadowrocket-configuration-file/refs/heads/main/rules/private.direct.list,DIRECT";
    added=1
  }
  print $0
}' base_config.conf > ru_config-private.conf
```

Update `ru_config-private.conf` to point to deduped lists (mirrors CI’s Perl step):

```sh
export DEDUP_RAW_PROXY="https://raw.githubusercontent.com/toffguy77/shadowrocket-configuration-file/refs/heads/main/rules/private.dedup.list"
export DEDUP_RAW_DIRECT="https://raw.githubusercontent.com/toffguy77/shadowrocket-configuration-file/refs/heads/main/rules/private.dedup-direct.list"

# Replace PROXY list URL to dedup
perl -0777 -pe 'BEGIN{$d=$ENV{"DEDUP_RAW_PROXY"}} s{RULE-SET,\s*https?://[^,]*private(?:\.dedup)?\.list\s*,}{"RULE-SET,$d,"}ig' ru_config-private.conf > /tmp/ru_config.tmp && mv /tmp/ru_config.tmp ru_config-private.conf

# Replace DIRECT list URL to dedup-direct (supports dot or dash separator)
perl -0777 -pe 'BEGIN{$d=$ENV{"DEDUP_RAW_DIRECT"}} s{RULE-SET,\s*https?://[^,]*private(?:\.dedup)?(?:[\.-])direct\.list\s*,}{"RULE-SET,$d,"}ig' ru_config-private.conf > /tmp/ru_config.tmp && mv /tmp/ru_config.tmp ru_config-private.conf
```

## Big-picture architecture

- Rules domain
  - Input: `rules/private.list` (PROXY), `rules/private.direct.list` (DIRECT)
  - Validation: `scripts/validate_rules.py` enforces UTF‑8 readability, known rule keys (DOMAIN/DOMAIN-SUFFIX/DOMAIN-KEYWORD, IP‑CIDR/IP‑CIDR6, RULE‑SET, FINAL, simple actions), correct CIDRs, valid RULE‑SET URLs, duplicate detection, and emits warnings for line length, trailing spaces, and unknown keys.
  - Deduplication: `scripts/dedup_rules.py` preserves comments/blank lines while removing duplicate rule lines (first occurrence wins).
  - Outputs: `rules/private.dedup.list`, `rules/private.dedup-direct.list` (consumed by the config).

- Config domain
  - `ru_config-private.conf` contains `[General]` network/DNS settings and a `[Rule]` section with multiple external RULE‑SETs plus private RULE‑SETs, followed by `FINAL,<target>`.
  - `scripts/validate_config.py` checks UTF‑8, presence of `[Rule]`, at least one `RULE-SET`, and a `FINAL,<target>`; also validates RULE‑SET URLs.
  - `.github/workflows/update-config.yml` periodically rebuilds `ru_config-private.conf` from an upstream base (`amatol/shadowrocket-configuration`) and injects private lists just before the first `FINAL,DIRECT`.

- CI orchestration
  - `.github/workflows/validate-and-dedup.yml` (on PR/push to rules/config):
    1) Setup Python 3.11 and install `requests`.
    2) Validate `rules/private.list` and `rules/private.direct.list` (including URL reachability).
    3) Validate `ru_config-private.conf`.
    4) Produce and validate deduped lists.
    5) If outputs changed, update `ru_config-private.conf` to reference deduped URLs and commit changes back to the branch.

## Notes and gotchas

- Files must be UTF‑8; comments use `#` or `//`.
- Keep at least one `RULE-SET` and a `FINAL,<target>` in `[Rule]` (validators and CI depend on this).
- URL reachability checks require `requests`; omit `--check-urls` if working fully offline.
- Deduped lists may be empty if inputs contain only comments/blank lines; that’s valid.
- The CI commit steps mutate the branch on change (ensure your local branch is in sync when developing new rules).

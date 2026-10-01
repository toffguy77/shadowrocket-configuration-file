#!/usr/bin/env python3
"""
Собрать Shadowrocket-листы из Re-filter-lists (РКН-блок-лист).

Зачем свой конвертер: Re-filter публикует только .srs/.dat (sing-box, xray) и
плоские .lst — ни одного файла в синтаксисе Shadowrocket. На домашнем роутере
используются ровно эти же списки через rule_set .srs, так что конвертация
здесь — единственный способ получить одинаковую маршрутизацию на телефоне и
на роутере.

Вход  (из релиза 1andrevich/Re-filter-lists):
  domains_all.lst — по одному домену в строке
  ipsum.lst       — по одному CIDR в строке
Выход (синтаксис Shadowrocket, подключается как RULE-SET):
  refilter-domains.list — DOMAIN-SUFFIX,<домен>
  refilter-ipsum.list   — IP-CIDR,<cidr>

Две оптимизации, обе безопасные:
  * домен выбрасывается, если его родительский суффикс уже есть в списке —
    DOMAIN-SUFFIX родителя покрывает всех потомков (-8%);
  * CIDR схлопываются через collapse_addresses (-8%).

Usage: build_refilter.py <domains_all.lst> <ipsum.lst> <outdir>
"""
import ipaddress
import re
import sys
from datetime import datetime, timezone

# Тот же шаблон, что в validate_rules.py — чтобы сгенерированное гарантированно
# проходило валидатор репозитория.
DOMAIN_RE = re.compile(r"^(?:\*\.)?[A-Za-z0-9\-](?:[A-Za-z0-9\-]|\.)*[A-Za-z0-9\-]$")

SRC = "https://github.com/1andrevich/Re-filter-lists"


def header(name, source_file, count, dropped):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return [
        f"# NAME: {name}",
        f"# SOURCE: {SRC} ({source_file})",
        f"# GENERATED: {ts} by scripts/build_refilter.py",
        f"# RULES: {count}" + (f" (отброшено невалидных: {dropped})" if dropped else ""),
        "# Не редактировать руками — файл пересобирается workflow refilter-sync.",
        "",
    ]


def build_domains(path):
    raw = [l.strip().lower() for l in open(path, encoding="utf-8") if l.strip()]
    present = set(raw)

    def covered_by_parent(d):
        parts = d.split(".")
        # i=1..len-2: собственный домен не считаем, TLD целиком не берём
        return any(".".join(parts[i:]) in present for i in range(1, len(parts) - 1))

    kept, dropped = [], 0
    seen = set()
    for d in raw:
        if not DOMAIN_RE.match(d):
            dropped += 1
            continue
        if covered_by_parent(d) or d in seen:
            continue
        seen.add(d)
        kept.append(d)
    return kept, dropped


def build_ips(path):
    nets, dropped = [], 0
    for l in open(path, encoding="utf-8"):
        l = l.strip()
        if not l:
            continue
        try:
            net = ipaddress.ip_network(l, strict=False)
        except ValueError:
            dropped += 1
            continue
        if net.version != 4:  # ipv6 на этом стеке выключен целиком
            dropped += 1
            continue
        nets.append(net)
    return [str(n) for n in ipaddress.collapse_addresses(nets)], dropped


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        return 2
    dom_src, ip_src, outdir = sys.argv[1:4]

    domains, dom_dropped = build_domains(dom_src)
    ips, ip_dropped = build_ips(ip_src)

    out_dom = f"{outdir}/refilter-domains.list"
    out_ip = f"{outdir}/refilter-ipsum.list"

    with open(out_dom, "w", encoding="utf-8") as f:
        f.write("\n".join(
            header("refilter-domains.list", "domains_all.lst", len(domains), dom_dropped)
            + [f"DOMAIN-SUFFIX,{d}" for d in domains]) + "\n")
    with open(out_ip, "w", encoding="utf-8") as f:
        f.write("\n".join(
            header("refilter-ipsum.list", "ipsum.lst", len(ips), ip_dropped)
            + [f"IP-CIDR,{c}" for c in ips]) + "\n")

    print(f"domains: {len(domains)} rules -> {out_dom}")
    print(f"ipsum:   {len(ips)} rules -> {out_ip}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

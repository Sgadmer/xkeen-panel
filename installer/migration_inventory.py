#!/usr/bin/env python3
"""Read a PRIVATE downloaded router snapshot and prepare a local migration report.

The report is never uploaded. Only simple, unambiguous direct domain/IP rules
become candidates; scope-sensitive and provider-specific rules remain for review.
"""
from __future__ import annotations
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re

def jsonc(text: str):
    out = []
    quoted = escaped = False
    i = 0
    while i < len(text):
        c = text[i]
        if quoted:
            out.append(c)
            if escaped: escaped = False
            elif c == '\\': escaped = True
            elif c == '"': quoted = False
        elif c == '"': quoted = True; out.append(c)
        elif text[i:i+2] == '//':
            while i < len(text) and text[i] not in '\r\n': i += 1
            continue
        elif text[i:i+2] == '/*':
            end = text.find('*/', i + 2)
            if end < 0: raise ValueError('Unterminated JSON comment')
            out.append(' '); i = end + 2; continue
        else: out.append(c)
        i += 1
    return json.loads(''.join(out))

def normalize(value: str) -> tuple[str, str] | None:
    if not isinstance(value, str): return None
    try: return 'ip', str(ipaddress.ip_address(value))
    except ValueError: pass
    try: return 'ip', str(ipaddress.ip_network(value, strict=False))
    except ValueError: pass
    kind, separator, host = value.partition(':')
    if kind not in {'domain', 'full'} or not separator: return None
    host = host.lower().rstrip('.')
    if '.' not in host or len(host) > 253: return None
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')): return None
    return kind, kind + ':' + host

def inventory(root: Path) -> dict:
    configs = root / 'opt/etc/xray/configs'
    if not configs.is_dir(): configs = root
    documents = []
    unreadable = []
    direct_tags = set()
    for path in sorted(configs.glob('*.json')):
        try:
            document = jsonc(path.read_text(encoding='utf-8-sig'))
            if not isinstance(document, dict): raise ValueError('Not an object')
        except (OSError, ValueError): unreadable.append(path.name); continue
        documents.append((path.name, document))
        for outbound in document.get('outbounds', []):
            if isinstance(outbound, dict) and outbound.get('protocol') == 'freedom' and isinstance(outbound.get('tag'), str): direct_tags.add(outbound['tag'])
    effective = next(((name, d['routing']) for name, d in reversed(documents) if isinstance(d.get('routing'), dict)), None)
    candidates, review = {}, []
    for index, rule in enumerate(effective[1].get('rules', []) if effective else []):
        if not isinstance(rule, dict): review.append({'index': index, 'reason': 'unknown-rule'}); continue
        if rule.get('outboundTag') not in direct_tags:
            review.append({'index': index, 'reason': 'proxy-block-or-balancer-rule', 'rule': rule}); continue
        allowed = {'type', 'ruleTag', 'outboundTag', 'domain', 'ip', 'inboundTag'}
        scope = rule.get('inboundTag', [])
        if set(rule) - allowed or (scope and set(scope) != {'redirect', 'tproxy'}) or ('domain' in rule and 'ip' in rule):
            review.append({'index': index, 'reason': 'conditions-or-input-scope-must-be-reviewed', 'rule': rule}); continue
        values = rule.get('domain', rule.get('ip', []))
        if not isinstance(values, list): review.append({'index': index, 'reason': 'invalid-address-list'}); continue
        for value in values:
            item = normalize(value)
            if item is None: review.append({'index': index, 'reason': 'category-regexp-or-unsupported-value', 'value': value}); continue
            kind, normalized = item
            identity = hashlib.sha256((kind + '\n' + normalized).encode()).hexdigest()[:32]
            candidates[identity] = {'id': identity, 'type': kind, 'value': normalized, 'comment': 'Перенесено после проверки прежних правил'}
    return {'schema': 1, 'effective_routing_file': effective[0] if effective else None, 'direct_candidates': list(candidates.values()), 'requires_review': review, 'unreadable_files': unreadable, 'notice': 'Кандидаты не применены. Сопоставьте старые и новые режимы, устройства, DNS и профиль; согласуйте перенос с пользователем.'}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Use a new private report path')
    report = inventory(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream: json.dump(report, stream, ensure_ascii=False, indent=2)
    print(json.dumps({'candidates': len(report['direct_candidates']), 'rules_to_review': len(report['requires_review']), 'unreadable_files': len(report['unreadable_files'])}))

if __name__ == '__main__': main()

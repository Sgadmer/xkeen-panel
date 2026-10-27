#!/usr/bin/env python3
"""Check the publishable Git tree without printing matched secret values."""
import argparse
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--tracked-only', action='store_true')
args = parser.parse_args()
command = ['git', 'ls-files', '-z']
if not args.tracked_only:
    command += ['--cached', '--others', '--exclude-standard']
names = set(subprocess.check_output(command, cwd=root).decode().split('\0')) - {''}
forbidden = {'.git', 'node_modules', 'data', 'build', '__pycache__'}
private = {'user.json', 'subscription.json', 'subscription-client.json', 'exclusions.json', 'key.txt', '.env', 'config.dev.yaml'}
home_prefix = b'C:' + bytes([92]) + b'Users' + bytes([92])
private_keys = [b'-----BEGIN ' + part + b'PRIVATE KEY-----' for part in (b'', b'RSA ', b'OPENSSH ', b'EC ')]
failures = []
for name in sorted(names):
    p = root / name
    if forbidden.intersection(Path(name).parts) or p.name in private or p.name.endswith(('.dpapi.json', '.log', '.tsbuildinfo')):
        failures.append((name, 'private/generated path'))
        continue
    if not p.is_file() or p.is_symlink():
        failures.append((name, 'not a regular source file'))
        continue
    content = p.read_bytes()
    if home_prefix.lower() in content.lower() or b'C:' + b'/Users/' in content:
        failures.append((name, 'personal workstation path'))
    if any(marker in content for marker in private_keys):
        failures.append((name, 'private key material'))
    if re.search(rb'(?:ghp_|github_pat_)[A-Za-z0-9_]{30,}', content):
        failures.append((name, 'GitHub credential pattern'))
for name, category in failures:
    print(f'FAIL {name}: {category}', file=sys.stderr)
print(f'Checked {len(names)} publishable files; private matches: {len(failures)}')
raise SystemExit(bool(failures))

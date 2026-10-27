#!/usr/bin/env python3
"""Write SHA256SUMS for immutable release assets after all builds finish."""
import argparse
import hashlib
from pathlib import Path

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--directory', type=Path, required=True)
    args = p.parse_args()
    files = sorted(path for path in args.directory.iterdir() if path.is_file() and path.name != 'SHA256SUMS')
    if not files:
        p.error('No release assets')
    (args.directory / 'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n' for path in files), encoding='ascii', newline='\n')

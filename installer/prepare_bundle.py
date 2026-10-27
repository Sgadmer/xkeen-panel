#!/usr/bin/env python3
"""Prepare an immutable, verified router bundle on the operator's computer.

No router credentials or subscription is required. Uses only public upstream
release APIs, never executes downloaded code on the computer.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import urllib.parse
import urllib.request
import zipfile

PANEL_REPO = 'Sgadmer/xkeen-panel'
MAX_DOWNLOAD = 256 * 1024 * 1024
ARCHES = {'aarch64': 'Xray-linux-arm64-v8a.zip', 'mipsel': 'Xray-linux-mips32le.zip'}

def fetch(url: str, limit: int = MAX_DOWNLOAD) -> bytes:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != 'https' or parsed.username or parsed.hostname not in {
        'api.github.com', 'github.com', 'objects.githubusercontent.com',
        'release-assets.githubusercontent.com', 'raw.githubusercontent.com',
    }:
        raise ValueError('Unsupported download origin')
    req = urllib.request.Request(url, headers={'User-Agent': 'xkeen-panel-installer/1', 'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(req, timeout=90) as response:
        final = urllib.parse.urlparse(response.url)
        if final.scheme != 'https' or final.hostname not in {'github.com', 'api.github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com', 'raw.githubusercontent.com'}:
            raise ValueError('Unexpected download redirect')
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Download exceeds size limit')
    return data

def release(repo: str, tag: str) -> dict:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,79}', tag) or tag in {'latest', 'main', 'master'}:
        raise ValueError('A fixed release tag is required')
    data = json.loads(fetch(f'https://api.github.com/repos/{repo}/releases/tags/{urllib.parse.quote(tag)}', 2 * 1024 * 1024))
    if data.get('draft') or data.get('tag_name') != tag:
        raise ValueError('Release identity mismatch')
    return data

def latest_fixed(repo: str) -> dict:
    info = json.loads(fetch(f'https://api.github.com/repos/{repo}/releases/latest', 2 * 1024 * 1024))
    tag = info.get('tag_name', '')
    # Geodata upstreams use a deliberately moving "latest" tag. Resolve it to
    # an immutable asset identity and SHA256, recorded in the bundle manifest.
    if not tag or info.get('draft'):
        raise ValueError('No usable geodata release')
    return info

def asset(info: dict, name: str) -> tuple[bytes, dict]:
    matches = [item for item in info.get('assets', []) if item.get('name') == name]
    if len(matches) != 1:
        raise ValueError(f'Release asset is missing or ambiguous: {name}')
    item = matches[0]
    digest = item.get('digest') or ''
    expected = digest.removeprefix('sha256:') if digest.startswith('sha256:') else ''
    if not re.fullmatch(r'[a-fA-F0-9]{64}', expected):
        # Older panel releases can provide a conventional checksum file.
        sums = [x for x in info.get('assets', []) if x.get('name') == 'SHA256SUMS']
        if len(sums) == 1:
            for line in fetch(sums[0]['browser_download_url'], 1024 * 1024).decode('ascii').splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1].lstrip('*') == name:
                    expected = parts[0]
        if not re.fullmatch(r'[a-fA-F0-9]{64}', expected):
            raise ValueError(f'Official SHA256 is unavailable for {name}; verification cannot be skipped')
    data = fetch(item['browser_download_url'])
    if len(data) != item.get('size') or hashlib.sha256(data).hexdigest() != expected.lower():
        raise ValueError(f'Asset integrity check failed: {name}')
    return data, {'release': info.get('tag_name'), 'asset_id': item['id'], 'asset': name, 'url': item['browser_download_url'], 'sha256': expected.lower(), 'bytes': len(data)}

def safe_member(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or '\\' in name or ':' in name or '..' in path.parts or any(not re.fullmatch(r'[A-Za-z0-9._-]+', part) for part in path.parts):
        raise ValueError('Unsafe archive path')
    return path

def unpack_xkeen(data: bytes, target: Path) -> None:
    seen = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
        for member in archive.getmembers():
            path = safe_member(member.name)
            if member.isdir():
                continue
            if not member.isfile() or member.size > 16 * 1024 * 1024:
                raise ValueError('Unsupported XKeen archive member')
            if str(path) == 'xkeen':
                relative = Path('core/xkeen')
            elif path.parts and path.parts[0] in {'_xkeen', '.xkeen'}:
                relative = Path('core/.xkeen', *path.parts[1:])
            else:
                raise ValueError('Unexpected XKeen archive layout')
            if relative.as_posix().casefold() in seen:
                raise ValueError('Duplicate XKeen archive path')
            seen.add(relative.as_posix().casefold())
            total += member.size
            if total > 64 * 1024 * 1024:
                raise ValueError('Unpacked XKeen exceeds size limit')
            output = target / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(archive.extractfile(member).read())
    if not (target / 'core/xkeen').is_file() or not (target / 'core/.xkeen/import.sh').is_file():
        raise ValueError('Incomplete XKeen archive')

def unpack_xray(data: bytes, arch: str = 'aarch64') -> bytes:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        selected = 'xray_softfloat' if arch == 'mipsel' and any(m.filename == 'xray_softfloat' for m in archive.infolist()) else 'xray'
        entries = [m for m in archive.infolist() if m.filename == selected]
        if len(entries) != 1 or entries[0].file_size > 128 * 1024 * 1024:
            raise ValueError('Unexpected Xray archive layout')
        if (entries[0].external_attr >> 16) & 0o170000 == 0o120000:
            raise ValueError('Xray is an archive symlink')
        return archive.read(entries[0])

def prepare(args: argparse.Namespace) -> dict:
    if args.output.exists():
        raise ValueError('Output directory already exists; use a new staging directory')
    if not re.fullmatch(r'v\d+\.\d+\.\d+(?:[.-][A-Za-z0-9.-]+)?', args.panel_version):
        raise ValueError('Invalid panel release tag')
    if not re.fullmatch(r'v?\d+\.\d+(?:\.\d+)?', args.xkeen_version) or not re.fullmatch(r'v?\d+\.\d+\.\d+', args.xray_version):
        raise ValueError('Use fixed XKeen/Xray versions')
    if not args.panel_only and args.xkeen_version.removeprefix('v') != '2.1':
        raise ValueError('Fresh installation adapter is validated for XKeen 2.1 only; a different release requires adapter review')
    if not args.panel_only:
        args.xkeen_version = '2.1'
    args.output.mkdir(parents=True)
    args.output.chmod(0o700)
    provenance = []
    try:
        panel, origin = asset(release(PANEL_REPO, args.panel_version), f'xkeen-panel-{args.arch}')
        (args.output / 'panel').write_bytes(panel)
        provenance.append(dict(component='panel', repository=PANEL_REPO, **origin))
        if not args.panel_only:
            xkeen, origin = asset(release('jameszeroX/XKeen', args.xkeen_version), 'xkeen.tar.gz')
            unpack_xkeen(xkeen, args.output)
            provenance.append(dict(component='xkeen', repository='jameszeroX/XKeen', **origin))
            xray, origin = asset(release('XTLS/Xray-core', args.xray_version), ARCHES[args.arch])
            (args.output / 'core/xray').write_bytes(unpack_xray(xray, args.arch))
            provenance.append(dict(component='xray', repository='XTLS/Xray-core', **origin))
            for component, repo, name, filename in [
                ('geosite-v2fly', 'v2fly/domain-list-community', 'dlc.dat', 'geosite_v2fly.dat'),
                ('geoip-v2fly', 'v2fly/geoip', 'geoip.dat', 'geoip_v2fly.dat'),
            ]:
                content, origin = asset(latest_fixed(repo), name)
                geodir = args.output / 'geodata'
                geodir.mkdir(exist_ok=True)
                (geodir / filename).write_bytes(content)
                provenance.append(dict(component=component, repository=repo, **origin))
        files = [{'path': p.relative_to(args.output).as_posix(), 'bytes': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(args.output.rglob('*')) if p.is_file()]
        manifest = {'schema': 1, 'repository': PANEL_REPO, 'panel_version': args.panel_version, 'xkeen_version': args.xkeen_version, 'xray_version': args.xray_version, 'architecture': args.arch, 'mode': 'panel' if args.panel_only else 'fresh', 'adapter': 'preserve-existing' if args.panel_only else 'xkeen-2.1-cores-none-v1', 'min_available_ram_kib': 65536, 'reserve_kib': 32768, 'files': files, 'provenance': provenance}
        raw = (json.dumps(manifest, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
        (args.output / 'bundle.json').write_bytes(raw)
        (args.output / 'SHA256SUMS').write_text(hashlib.sha256(raw).hexdigest() + '  bundle.json\n', encoding='ascii')
        return manifest
    except BaseException:
        # This exact directory was created by this invocation; keep a tiny
        # failure marker, but remove downloaded executable payloads.
        assert args.output.resolve().is_relative_to(args.output.parent.resolve())
        shutil.rmtree(args.output)
        raise

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--panel-version', required=True)
    parser.add_argument('--xkeen-version', default='2.1')
    parser.add_argument('--xray-version', default='v26.3.27')
    parser.add_argument('--arch', choices=ARCHES, required=True)
    parser.add_argument('--panel-only', action='store_true', help='Preserve an existing working XKeen/Xray stack')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args)
    print(json.dumps({'bundle': str(args.output), 'files': len(result['files']), 'mode': result['mode'], 'architecture': result['architecture']}, ensure_ascii=False))

if __name__ == '__main__':
    main()

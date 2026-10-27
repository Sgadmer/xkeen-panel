from pathlib import Path
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[2]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

bundle = load('prepare_bundle', REPO / 'installer/prepare_bundle.py')
migration = load('migration_inventory', REPO / 'installer/migration_inventory.py')

class BundleTests(unittest.TestCase):
    def test_reject_archive_escape_and_links(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('/absolute', tarfile.REGTYPE), ('_xkeen/link', tarfile.SYMTYPE)]:
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w:gz') as archive:
                member = tarfile.TarInfo(name); member.type = kind; member.size = 1 if kind == tarfile.REGTYPE else 0
                archive.addfile(member, io.BytesIO(b'x') if member.size else None)
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError): bundle.unpack_xkeen(stream.getvalue(), Path(directory))
                self.assertFalse((Path(directory).parent / 'escape').exists())

    def test_xkeen_layout_and_xray_single_binary(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for name in ['xkeen', '_xkeen/import.sh', '_xkeen/01_info/example.sh']:
                member = tarfile.TarInfo(name); member.size = 4; archive.addfile(member, io.BytesIO(b'test'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); bundle.unpack_xkeen(stream.getvalue(), root)
            self.assertEqual((root / 'core/.xkeen/import.sh').read_bytes(), b'test')
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('xray', b'ELF-test'); archive.writestr('README.md', b'unused')
        self.assertEqual(bundle.unpack_xray(stream.getvalue()), b'ELF-test')

    def test_asset_digest_is_mandatory_and_checked(self):
        original = bundle.fetch
        try:
            bundle.fetch = lambda url, limit=bundle.MAX_DOWNLOAD: b'abc'
            info = {'tag_name': 'v1.0.0', 'assets': [{'name': 'binary', 'size': 3, 'id': 1, 'browser_download_url': 'https://github.com/example/repo/releases/download/v1.0.0/binary'}]}
            with self.assertRaises(ValueError): bundle.asset(info, 'binary')
            info['assets'][0]['digest'] = 'sha256:' + '0' * 64
            with self.assertRaises(ValueError): bundle.asset(info, 'binary')
            info['assets'][0]['digest'] = 'sha256:' + hashlib.sha256(b'abc').hexdigest()
            self.assertEqual(bundle.asset(info, 'binary')[0], b'abc')
        finally: bundle.fetch = original

    def test_mips_uses_softfloat_binary_when_provided(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('xray', b'hardfloat'); archive.writestr('xray_softfloat', b'softfloat')
        self.assertEqual(bundle.unpack_xray(stream.getvalue(), 'mipsel'), b'softfloat')
        self.assertEqual(bundle.unpack_xray(stream.getvalue(), 'aarch64'), b'hardfloat')

    def test_unknown_fresh_xkeen_adapter_is_rejected_before_download(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'bundle'
            args = SimpleNamespace(output=output, panel_version='v3.0.0-beta.1', xkeen_version='2.2', xray_version='v26.3.27', panel_only=False, arch='aarch64')
            with self.assertRaisesRegex(ValueError, 'adapter'): bundle.prepare(args)
            self.assertFalse(output.exists())

    def test_no_arbitrary_download_origin(self):
        for url in ['http://github.com/a', 'https://attacker.example/a', 'https://user:pass@github.com/a']:
            with self.assertRaises(ValueError): bundle.fetch(url)

class MigrationTests(unittest.TestCase):
    def test_preserve_json_strings_and_comment_syntax(self):
        data = migration.jsonc('{// comment\n"url":"https://example.com/a/*literal*/",/* x */"n":1}')
        self.assertEqual(data['url'], 'https://example.com/a/*literal*/')

    def test_only_unambiguous_direct_rules_are_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '04_outbounds.json').write_text(json.dumps({'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}, {'tag': 'proxy', 'protocol': 'vless'}]}))
            rules = [
                {'outboundTag': 'direct', 'inboundTag': ['redirect', 'tproxy'], 'domain': ['domain:example.com', 'full:api.example.com', 'geosite:ru']},
                {'outboundTag': 'direct', 'ip': ['192.0.2.33/24']},
                {'outboundTag': 'direct', 'domain': ['domain:private.example.com'], 'port': '443'},
                {'outboundTag': 'proxy', 'domain': ['domain:via-vpn.example.com']},
            ]
            (root / '05_routing.json').write_text(json.dumps({'routing': {'rules': rules}}))
            result = migration.inventory(root)
            self.assertEqual({e['value'] for e in result['direct_candidates']}, {'domain:example.com', 'full:api.example.com', '192.0.2.0/24'})
            self.assertEqual(len(result['requires_review']), 3)
            self.assertFalse(any(e['value'].endswith('via-vpn.example.com') for e in result['direct_candidates']))

    def test_last_routing_document_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '01.json').write_text(json.dumps({'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}], 'routing': {'rules': [{'outboundTag': 'direct', 'domain': ['domain:old.example.com']}]}}))
            (root / '05.json').write_text(json.dumps({'routing': {'rules': [{'outboundTag': 'direct', 'domain': ['domain:new.example.com']}]}}))
            result = migration.inventory(root)
            self.assertEqual(result['effective_routing_file'], '05.json')
            self.assertEqual([e['value'] for e in result['direct_candidates']], ['domain:new.example.com'])

def shell_path(path):
    value = Path(path).as_posix()
    if os.name == 'nt' and len(value) > 2 and value[1] == ':':
        return '/' + value[0].lower() + value[2:]
    return value

@unittest.skipIf(os.name == 'nt' and os.environ.get('XKP_POSIX_TESTS') != '1', 'POSIX integration runs in Linux CI; opt in on Windows with a real POSIX shell and jq')
class InstallIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'router'; self.root.mkdir()
        (self.root / 'opt/etc/init.d').mkdir(parents=True)
        (self.root / 'proc').mkdir(); (self.root / 'proc/meminfo').write_text('MemAvailable: 262144 kB\n')
        self.bundle = Path(self.temp.name) / 'bundle'; self.bundle.mkdir()
        self.commands = Path(self.temp.name) / 'bin'; self.commands.mkdir()
        self.env = dict(os.environ, XKP_INSTALL_TESTING='1', XKP_TEST_ROOT=shell_path(self.root), PATH=str(self.commands) + os.pathsep + os.environ['PATH'])
        if os.name == 'nt':
            # The bundled Git shell lacks some coreutils. These test-only
            # adapters perform real hashing/disk accounting/timeouts on Windows;
            # Linux CI uses the actual POSIX tools.
            helper = shell_path(Path(__file__).with_name('posix_fixture_tools.py'))
            python = shell_path(sys.executable)
            self.env['XKP_TEST_SHELL'] = shutil.which('sh')
            self.env['XKP_TEST_TAR'] = shutil.which('tar')
            actual_jq = shutil.which('jq')
            if not actual_jq:
                self.skipTest('Windows POSIX fixture needs official jq in PATH')
            self.write(self.commands / 'jq', f'#!/bin/sh\nexec "{shell_path(actual_jq)}" -b "$@"\n')
            for name in ['sha256sum', 'df', 'du', 'chmod', 'timeout', 'tar']:
                self.write(self.commands / name, f'#!/bin/sh\nexec "{python}" "{helper}" {name} "$@"\n')
        self.write(self.commands / 'id', '#!/bin/sh\necho 0\n')
        self.write(self.commands / 'opkg', '#!/bin/sh\necho "arch aarch64-3.10 10"\n')
        self.write(self.commands / 'uname', '#!/bin/sh\ncase "$1" in -m) echo aarch64;; *) echo 5.10;; esac\n')
        self.write(self.commands / 'pidof', '#!/bin/sh\nif [ "$1" = xkeen-panel ] && [ -f "$XKP_TEST_ROOT/panel-running" ]; then echo 1234; exit 0; fi\nexit 1\n')
        self.write(self.commands / 'curl', '#!/bin/sh\n[ ! -e "$XKP_TEST_ROOT/fail-health" ] || exit 22\necho \'{"setup_required":true}\'\n')
        self.write(self.commands / 'sleep', '#!/bin/sh\nexit 0\n')
        self.write(self.root / '.test-service', '#!/bin/sh\nprintf "%s %s\\n" "$1" "$2" >> "$XKP_TEST_ROOT/services.log"\ncase "$1:$2" in *S99xkeen-panel:stop) rm -f "$XKP_TEST_ROOT/panel-running";; esac\n')

    def write(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text); path.chmod(0o700)

    def prepare(self, mode='fresh'):
        self.write(self.bundle / 'panel', '#!/bin/sh\necho "XKeen Panel v3.0.0-beta.1"\n')
        if mode == 'fresh':
            self.write(self.bundle / 'core/xray', '#!/bin/sh\necho "Xray 26.3.27"\n')
            self.write(self.bundle / 'core/xkeen', '''#!/bin/sh
if [ "$1" = -v ]; then echo 'XKeen 2.1'; exit 0; fi
[ "$*" = '-i auto cores=none geo=off geoipset=off cron=off autostart=off' ] || exit 2
mkdir -p "$XKP_TEST_ROOT/opt/etc/xray/configs" "$XKP_TEST_ROOT/opt/etc/xkeen"
printf '#!/bin/sh\\nexit 0\\n' > "$XKP_TEST_ROOT/opt/etc/init.d/S05xkeen"
chmod +x "$XKP_TEST_ROOT/opt/etc/init.d/S05xkeen"
''')
            self.write(self.bundle / 'core/.xkeen/import.sh', '# synthetic fixture\n')
            self.write(self.bundle / 'geodata/geoip_v2fly.dat', 'synthetic-geoip')
            self.write(self.bundle / 'geodata/geosite_v2fly.dat', 'synthetic-geosite')
        files = [{'path': p.relative_to(self.bundle).as_posix(), 'bytes': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in self.bundle.rglob('*') if p.is_file()]
        manifest = {'schema': 1, 'repository': 'Sgadmer/xkeen-panel', 'panel_version': 'v3.0.0-beta.1', 'xkeen_version': '2.1', 'xray_version': 'v26.3.27', 'architecture': 'aarch64', 'mode': mode, 'adapter': 'xkeen-2.1-cores-none-v1' if mode == 'fresh' else 'preserve-existing', 'min_available_ram_kib': 65536, 'reserve_kib': 1024, 'files': files}
        raw = json.dumps(manifest).encode(); (self.bundle / 'bundle.json').write_bytes(raw)
        (self.bundle / 'SHA256SUMS').write_text(hashlib.sha256(raw).hexdigest() + '  bundle.json\n')

    def run_install(self, *args):
        return subprocess.run(['sh', shell_path(REPO / 'install.sh'), '--test-root', shell_path(self.root), '--bundle', shell_path(self.bundle), '--preflight-reviewed', *args], env=self.env, text=True, encoding='utf-8', errors='replace', stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_fresh_installs_exact_core_and_leaves_it_stopped(self):
        self.prepare(); result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / 'opt/sbin/xkeen-panel').is_file())
        self.assertTrue((self.root / 'opt/etc/xray/dat/geosite_v2fly.dat').is_file())
        log = (self.root / 'services.log').read_text()
        self.assertIn('S05xkeen stop', log); self.assertNotIn('S05xkeen start', log)

    def test_corrupt_payload_never_touches_managed_files(self):
        self.prepare(); (self.bundle / 'panel').write_text('tampered')
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'opt/sbin/xray').exists())

    def test_unlisted_payload_is_rejected(self):
        self.prepare(); (self.bundle / 'core/.xkeen/extra.sh').write_text('unverified')
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'opt/sbin/xray').exists())

    def test_start_failure_rolls_back_fresh_stack(self):
        self.prepare(); (self.root / 'fail-health').touch()
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'opt/sbin/xray').exists())
        self.assertFalse((self.root / 'opt/sbin/xkeen-panel').exists())
        self.assertIn('восстановлены', result.stdout)

    def test_existing_stack_requires_migration_and_is_preserved(self):
        self.prepare('panel')
        self.write(self.root / 'opt/sbin/xkeen', '#!/bin/sh\necho old\n')
        self.write(self.root / 'opt/sbin/xray', '#!/bin/sh\necho old-core\n')
        before = (self.root / 'opt/sbin/xray').read_bytes()
        self.assertNotEqual(self.run_install().returncode, 0)
        result = self.run_install('--migration-reviewed')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'opt/sbin/xray').read_bytes(), before)

    def test_corrupt_resume_snapshot_cannot_delete_live_files(self):
        self.prepare(); (self.root / 'fail-health').touch()
        self.assertNotEqual(self.run_install().returncode, 0)
        stage = next((self.root / 'opt/etc').glob('xkeen-panel-install.*'))
        (stage / 'before.tar').write_bytes(b'corrupted snapshot')
        live = self.root / 'opt/sbin/xray'; live.parent.mkdir(parents=True, exist_ok=True); live.write_bytes(b'preserve-current-live-core')
        result = self.run_install('--resume', shell_path(stage), '--migration-reviewed')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(live.read_bytes(), b'preserve-current-live-core')

    def test_resume_reuses_verified_bundle_after_rollback(self):
        self.prepare(); (self.root / 'fail-health').touch()
        self.assertNotEqual(self.run_install().returncode, 0)
        stage = next((self.root / 'opt/etc').glob('xkeen-panel-install.*'))
        (self.root / 'fail-health').unlink()
        result = self.run_install('--resume', shell_path(stage), '--migration-reviewed')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / 'opt/sbin/xkeen-panel').is_file())

    def test_failed_panel_migration_restores_data_and_core(self):
        self.prepare('panel')
        self.write(self.root / 'opt/sbin/xkeen', '#!/bin/sh\necho old\n')
        self.write(self.root / 'opt/sbin/xray', '#!/bin/sh\necho old-core\n')
        self.write(self.root / 'opt/sbin/xkeen-panel', '#!/bin/sh\necho old-panel\n')
        data = self.root / 'opt/etc/xkeen-panel/data/exclusions.json'
        data.parent.mkdir(parents=True); data.write_bytes(b'{"entries":[]}\n')
        before = {str(p.relative_to(self.root)): p.read_bytes() for p in [data, self.root / 'opt/sbin/xray', self.root / 'opt/sbin/xkeen-panel']}
        (self.root / 'fail-health').touch()
        result = self.run_install('--migration-reviewed')
        self.assertNotEqual(result.returncode, 0)
        for name, body in before.items(): self.assertEqual((self.root / name).read_bytes(), body)

    def test_running_panel_is_paused_before_consistent_snapshot(self):
        self.prepare('panel')
        self.write(self.root / 'opt/sbin/xkeen', '#!/bin/sh\necho old\n')
        self.write(self.root / 'opt/sbin/xray', '#!/bin/sh\necho old-core\n')
        self.write(self.root / 'opt/etc/init.d/S99xkeen-panel', '#!/bin/sh\nexit 0\n')
        (self.root / 'panel-running').touch()
        result = self.run_install('--migration-reviewed')
        self.assertEqual(result.returncode, 0, result.stderr)
        stages = list((self.root / 'opt/etc').glob('xkeen-panel-install.*'))
        self.assertEqual((stages[0] / 'panel-running').read_text().strip(), '1')
        log = (self.root / 'services.log').read_text().splitlines()
        self.assertTrue(log[0].endswith('S99xkeen-panel stop'))

    def test_check_does_not_create_installation_paths(self):
        before = {p.relative_to(self.root) for p in self.root.rglob('*')}
        result = subprocess.run(['sh', shell_path(REPO / 'install.sh'), '--test-root', shell_path(self.root), '--check'], env=self.env, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(before, {p.relative_to(self.root) for p in self.root.rglob('*')})

if __name__ == '__main__': unittest.main()

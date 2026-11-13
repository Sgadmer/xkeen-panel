from pathlib import Path
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


INSTALLER = Path(__file__).resolve().parents[1]
POOLS = {'iptables': ['198.18.0.0/15', '160.79.104.0/23', '153.61.224.0/22'],
         'ip6tables': ['2001:2::/48', '2607:6bc0::/48']}


def shell_path(path):
    path = Path(path).as_posix()
    if os.name == 'nt' and len(path) > 2 and path[1] == ':':
        return '/' + path[0].lower() + path[2:]
    return path


def mock_xtables(tool, arguments):
    """Allow exactly the real commands the guard needs. Commit all or nothing."""
    restoring = tool.endswith('-restore')
    family = tool.removesuffix('-restore')
    state = Path(os.environ['GUARD_FIXTURE']) / family
    if family not in POOLS or not state.exists():
        return 1
    rules = state.read_text().splitlines()
    if not restoring:
        if arguments != ['-t', 'filter', '-S']:
            return 2
        sys.stdout.buffer.write(('\n'.join(rules) + '\n').encode())
        return 0
    if arguments != ['--noflush']:
        return 2
    lines = sys.stdin.read().splitlines()
    if lines[0] != '*filter' or lines[-1] != 'COMMIT':
        return 2
    for line in lines[1:-1]:
        action, chain, dst, prefix, target, verdict = line.split()
        if chain not in ('FORWARD', 'OUTPUT') or prefix not in POOLS[family] or (dst, target, verdict) != ('-d', '-j', 'DROP'):
            return 2
        rule = '-A' + line[2:]
        if action == '-I':
            rules.insert(0, rule)
        elif action == '-D' and rule in rules:
            rules.remove(rule)
        else:
            return 2
    if os.environ.get('GUARD_FAIL_FAMILY') == family:
        return 1
    state.write_text('\n'.join(rules) + '\n')
    with (state.parent / 'commits').open('a') as audit:
        audit.write(family + '\n')
    return 0


class SelectiveGuardTests(unittest.TestCase):
    def setUp(self):
        shell = shutil.which('sh')
        if not shell and os.name == 'nt' and shutil.which('git'):
            git_shell = Path(shutil.which('git')).parents[1] / 'usr/bin/sh.exe'
            if git_shell.is_file():
                shell = str(git_shell)
        if not shell:
            self.skipTest('POSIX shell unavailable')
        self.shell = shell
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        bin_dir = self.root / 'bin'
        bin_dir.mkdir()
        self.env = dict(os.environ, GUARD_FIXTURE=str(self.root))
        self.env['PATH'] = os.pathsep.join([str(bin_dir), str(Path(shell).parent), os.environ['PATH']])
        for family in POOLS:
            for name in [family, family + '-restore']:
                tool = bin_dir / name
                cmd = [shell_path(sys.executable), shell_path(__file__), 'mock', name]
                tool.write_bytes(('#!/bin/sh\nexec ' + shlex.join(cmd) + ' "$@"\n').encode())
                tool.chmod(0o755)
            (self.root / family).write_text('-P FORWARD ACCEPT\n-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n-A INPUT -j ACCEPT\n-A FORWARD -m conntrack --ctstate ESTABLISHED -j ACCEPT\n-A OUTPUT -j ACCEPT\n')

    def run_guard(self, *args, script='strict-guard.sh', **env):
        return subprocess.run([self.shell, shell_path(INSTALLER / script), *args],
                              env=dict(self.env, **env), capture_output=True, timeout=20)

    def test_direct_rules_and_local_dns_survive_and_reapply_is_a_noop(self):
        self.assertNotEqual(self.run_guard('check').returncode, 0)
        self.assertFalse((self.root / 'commits').exists())
        before = {f: (self.root / f).read_text().splitlines() for f in POOLS}
        res = self.run_guard('apply')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(self.run_guard('check').stdout.strip(), b'selective-firewall-ready')
        self.assertEqual(self.run_guard('apply').returncode, 0)
        self.assertEqual((self.root / 'commits').read_text().splitlines(), list(POOLS))
        for family, prefixes in POOLS.items():
            after = (self.root / family).read_text().splitlines()
            rules = [f'-A {chain} -d {prefix} -j DROP' for prefix in prefixes for chain in ('FORWARD', 'OUTPUT')]
            self.assertEqual(after[len(rules):], before[family])
            self.assertCountEqual(after[:len(rules)], rules)

    def test_preceding_accept_is_unsafe_for_both_chains_and_families(self):
        self.assertEqual(self.run_guard('apply').returncode, 0)
        for family, prefixes in POOLS.items():
            for chain in ['OUTPUT', 'FORWARD']:
                path = self.root / family
                path.write_text(f'-A {chain} -j ACCEPT\n' + path.read_text())
                self.assertNotEqual(self.run_guard('check').returncode, 0)
                self.assertEqual(self.run_guard('apply').returncode, 0)
                for prefix in prefixes:
                    self.assertEqual(path.read_text().count(f'-A {chain} -d {prefix} -j DROP'), 1)

    def test_partial_failure_retains_ipv4_but_never_reports_ready(self):
        v6 = self.root / 'ip6tables'
        before = v6.read_bytes()
        result = self.run_guard('apply', GUARD_FAIL_FAMILY='ip6tables')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b'ready', result.stdout)
        self.assertEqual(v6.read_bytes(), before)
        self.assertEqual((self.root / 'commits').read_text().splitlines(), ['iptables'])
        self.assertEqual(self.run_guard('apply').returncode, 0)
        v6.unlink()
        self.assertNotEqual(self.run_guard('check').returncode, 0)

    def test_stop_and_nonfilter_events_change_nothing(self):
        self.assertEqual(self.run_guard('stop', script='S01xkeen-panel-guard').returncode, 0)
        self.assertEqual(self.run_guard(script='99-xkeen-panel-guard.sh', table='nat', type='iptables').returncode, 0)
        self.assertNotEqual(self.run_guard('stop').returncode, 0)
        self.assertFalse((self.root / 'commits').exists())

    def test_prefix_check_does_not_attest_a_domain_policy(self):
        self.assertEqual(self.run_guard('apply').returncode, 0)
        result = self.run_guard('check-policy')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b'firewall-ready', result.stdout)

    def test_api_only_scope_and_safe_traffic_fixture(self):
        import ipaddress
        self.assertEqual(self.run_guard('apply-api').returncode, 0)
        self.assertEqual(self.run_guard('check-api').stdout.strip(), b'anthropic-api-firewall-ready')
        self.assertNotEqual(self.run_guard('check').returncode, 0)
        self.assertNotEqual(self.run_guard('check-policy').returncode, 0)
        destinations = {'160.79.104.17': 'DROP', '153.61.227.10': 'DROP', '2607:6bc0::2': 'DROP',
                        '192.0.2.11': 'ACCEPT', '2001:db8::11': 'ACCEPT', '198.18.0.11': 'ACCEPT',
                        '2001:2::11': 'ACCEPT'}
        for dst, expected in destinations.items():
            addr = ipaddress.ip_address(dst)
            family = 'iptables' if addr.version == 4 else 'ip6tables'
            for chain in ('FORWARD', 'OUTPUT'):
                # Feed synthetic established traffic through the fixture in
                # actual chain order. Existing default route/ACCEPT is retained.
                decision = None
                for rule in (self.root / family).read_text().splitlines():
                    words = rule.split()
                    if words[:2] != ['-A', chain]:
                        continue
                    if '-d' in words and addr not in ipaddress.ip_network(words[words.index('-d') + 1]):
                        continue
                    decision = words[words.index('-j') + 1]
                    break
                self.assertEqual(decision, expected, (chain, dst))

    def test_managed_companion_install_and_conflict(self):
        # Give the exact router scripts an isolated /opt and fake root UID.
        # Never add an environment override to the production privileged path.
        opt = self.root / 'opt'
        for directory in ('sbin', 'etc/init.d', 'etc/ndm/netfilter.d'):
            (opt / directory).mkdir(parents=True)
        source = self.root / 'source'
        source.mkdir()
        for name in ('install-claude-guard.sh', 'strict-guard.sh', 'S01xkeen-panel-guard', '99-xkeen-panel-guard.sh'):
            script = (INSTALLER / name).read_text().replace('/opt/', shell_path(opt) + '/')
            (source / name).write_bytes(script.encode())
        for name, body in {'id': 'printf "0\\n"', 'chmod': 'exit 0'}.items():
            if name == 'chmod' and os.name != 'nt':
                continue
            exe = self.root / 'bin' / name
            exe.write_bytes(('#!/bin/sh\n' + body + '\n').encode())
            exe.chmod(0o755)
        if os.name == 'nt' and not (Path(self.shell).parent / 'ln.exe').is_file():
            exe = self.root / 'bin/ln'
            command = [shell_path(sys.executable), '-c', 'import os,sys; os.link(*sys.argv[1:])']
            exe.write_bytes(('#!/bin/sh\nexec ' + shlex.join(command) + ' "$@"\n').encode())
            exe.chmod(0o755)
        command = [self.shell, shell_path(source / 'install-claude-guard.sh'), 'install']
        for _ in range(2):
            result = subprocess.run(command, env=self.env, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'commits').read_text().splitlines(), list(POOLS))
        hook = opt / 'etc/ndm/netfilter.d/99-xkeen-panel-guard.sh'
        hook.write_bytes(b'#!/bin/sh\n# preexisting operator version\n')
        self.assertNotEqual(subprocess.run(command, env=self.env, capture_output=True).returncode, 0)
        self.assertIn(b'preexisting operator', hook.read_bytes())


if __name__ == '__main__':
    if len(sys.argv) > 2 and sys.argv[1] == 'mock':
        raise SystemExit(mock_xtables(sys.argv[2], sys.argv[3:]))
    unittest.main()

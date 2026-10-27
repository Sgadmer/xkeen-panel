"""Test-only adapters for coreutils absent from the Windows Git shell."""
from pathlib import Path
import hashlib
import os
import shutil
import subprocess
import sys

command, *args = sys.argv[1:]
if command == 'sha256sum':
    for name in args:
        p = Path(name)
        print(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + name)
elif command == 'df':
    path = Path(args[-1]); usage = shutil.disk_usage(path)
    print('Filesystem 1024-blocks Used Available Capacity Mounted on')
    print(f'test {usage.total // 1024} {usage.used // 1024} {usage.free // 1024} 1% {path}')
elif command == 'du':
    for name in [a for a in args if not a.startswith('-')]:
        p = Path(name)
        if not p.exists(): continue
        size = sum(c.stat().st_size for c in p.rglob('*') if c.is_file()) if p.is_dir() else p.stat().st_size
        print(f'{(size + 1023) // 1024}\t{name}')
elif command == 'chmod':
    # Windows does not expose POSIX execute permissions. Linux CI verifies the
    # actual command/permissions; this adapter only permits the fixture run.
    sys.exit(0)
elif command == 'timeout':
    seconds, executable, *rest = args
    value = Path(executable).as_posix()
    if len(value) > 2 and value[1] == ':': value = '/' + value[0].lower() + value[2:]
    try:
        result = subprocess.run([os.environ['XKP_TEST_SHELL'], value, *rest], timeout=float(seconds))
        sys.exit(result.returncode)
    except subprocess.TimeoutExpired: sys.exit(124)
elif command == 'tar':
    # Native Windows BSD tar writes CRLF/localized listings; the production
    # Linux command writes LF. Preserve real archive operations and normalize
    # only the textual command output for this Windows fixture.
    result = subprocess.run([os.environ['XKP_TEST_TAR'], *args], capture_output=True)
    for output, target in [(result.stdout, sys.stdout), (result.stderr, sys.stderr)]:
        try: value = output.decode('utf-8')
        except UnicodeDecodeError: value = output.decode('mbcs', errors='replace')
        target.buffer.write(value.replace('\r\n', '\n').encode('utf-8'))
    sys.exit(result.returncode)
else:
    raise SystemExit('unsupported test adapter')

#!/usr/bin/env python3
"""Check that the SHA256SUMS of a panel release were approved with a release key.

GitHub stores the release files, so whoever controls the repository can replace
a binary together with its checksums. The signature is made on the maintainer's
computer with a key that never reaches GitHub. Standard library only: Ed25519
verification follows the reference code of RFC 8032.

The message and the keys are the same as in internal/releasesig of the panel:
both read the keys from one file, the only place a fork has to replace.
"""
from __future__ import annotations
import base64
import hashlib
from pathlib import Path

ASSET = 'SHA256SUMS.sig'
PURPOSE = b'xkeen-panel release checksums v1'
KEYS_FILE = Path(__file__).resolve().parent.parent.joinpath('internal', 'releasesig', 'release-keys.txt')
MAX_SIGNATURES = 8


def load_keys(path: Path = KEYS_FILE) -> tuple[str, ...]:
    """The public halves of the release keys. No readable file means no trusted key."""
    try:
        lines = path.read_text(encoding='utf-8').splitlines()
    except OSError:
        return ()
    keys = []
    for line in lines:
        fields = line.split()
        if fields and not fields[0].startswith('#'):
            keys.append(fields[0])
    return tuple(keys)


TRUSTED_KEYS = load_keys()

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _add(a, b):
    # Extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, x*y = T/Z.
    e = (a[1] - a[0]) * (b[1] - b[0]) % _P
    f = (a[1] + a[0]) * (b[1] + b[0]) % _P
    g = 2 * a[3] * b[3] * _D % _P
    h = 2 * a[2] * b[2] % _P
    i, j, k, m = f - e, h - g, h + g, f + e
    return (i * j % _P, k * m % _P, j * k % _P, i * m % _P)


def _multiply(scalar: int, point):
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _same(a, b) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _point(raw: bytes):
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, 'little')
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


_BASE_Y = 4 * pow(5, _P - 2, _P) % _P
_BASE_X = _recover_x(_BASE_Y, 0)
_BASE = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % _P)


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    key, commitment = _point(public), _point(signature[:32])
    if key is None or commitment is None:
        return False
    scalar = int.from_bytes(signature[32:], 'little')
    if scalar >= _L:
        return False
    challenge = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), 'little') % _L
    return _same(_multiply(scalar, _BASE), _add(commitment, _multiply(challenge, key)))


def message(tag: str, sums: bytes) -> bytes:
    """What a signature covers: the purpose, the tag, the exact bytes of SHA256SUMS."""
    return PURPOSE + b'\n' + tag.encode('utf-8') + b'\n' + sums


def verify_release(tag: str, sums: bytes, signatures: bytes, trusted=None) -> bool:
    """True when any line of the signature file was made by any trusted key."""
    if not tag.strip() or '\n' in tag or '\r' in tag:
        return False
    try:
        keys = [base64.b64decode(key, validate=True) for key in (TRUSTED_KEYS if trusted is None else trusted)]
    except ValueError:
        return False
    if not keys:
        return False
    signed = message(tag, sums)
    seen = 0
    for line in signatures.decode('ascii', 'replace').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        seen += 1
        if seen > MAX_SIGNATURES:
            break
        try:
            signature = base64.b64decode(line, validate=True)
        except ValueError:
            continue
        if any(ed25519_verify(key, signed, signature) for key in keys):
            return True
    return False

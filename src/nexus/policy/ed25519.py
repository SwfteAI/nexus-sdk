"""Ed25519 signature verification, pure stdlib.

Ported verbatim from ``nexus_devtools/ed25519.py``. Kept byte-identical in substance on purpose:
the same private key signs envelopes for both the CLI and this SDK, so any divergence between the
two verifiers is a policy that one attach point honours and the other rejects.

Why this file exists at all: the policy envelope that can deny an action is held on disk and in
memory inside the customer's own process, which the customer controls. A rule set that a text
editor defeats is not enforcement, so the control plane signs the envelope and we verify before
honouring it — including before honouring a *cached* deny.

Why hand-rolled rather than ``cryptography``: this package declares zero runtime dependencies on
purpose (case 7.5), so it installs into a bare environment and imports with no wheels to resolve.
Verification happens on envelope load, not per decision, so the cost of a pure-Python
implementation stays off the hot path entirely — see ``engine.Snapshot``.

Why asymmetric rather than an HMAC: whatever key ships inside the artifact is extractable by
anyone willing to work for it. An HMAC secret would then let them *forge* an "allow" — or, worse
in our case, forge an envelope with the enforce markings stripped. An Ed25519 public key lets them
do nothing but check our arithmetic.

The implementation below is the reference code from RFC 8032 §6, unmodified in substance — this
is deliberately not the place for original cryptographic engineering. ``tests/test_policy.py``
runs it against the RFC's own published test vectors; a verifier that silently returns True would
be far worse than no verifier at all, so that test is not optional.

``sign`` and ``public_key`` are at the bottom. The SDK never signs anything in production — only
the control plane holds a private key. They exist so the test suite can exercise verification
against *real* signatures over *real* envelopes. The alternative is mocking the verifier, which
would assert our own beliefs back to us and is precisely how a verifier that always returns True
reaches production.
"""
from __future__ import annotations

import hashlib

# Curve25519 field prime and group order.
_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493


def _modp_inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = -121665 * _modp_inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _sha512_modq(s: bytes) -> int:
    return int.from_bytes(hashlib.sha512(s).digest(), "little") % _Q


# Points are (X, Y, Z, T) in extended homogeneous coordinates: x = X/Z, y = Y/Z, x*y = T/Z.
# Extended coordinates keep modular inversion out of the scalar-multiplication loop, which is the
# difference between ~10ms and ~2s per verification — and this runs on the CLI's startup path.

def _point_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _P
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _P
    C = 2 * P[3] * Q[3] * _D % _P
    D = 2 * P[2] * Q[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F, G * H, F * G, E * H)


def _point_mul(s: int, P):
    Q = (0, 1, 1, 0)  # neutral element
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _point_equal(P, Q) -> bool:
    # Compare projectively: x/z and y/z must match, without inverting z.
    if (P[0] * Q[2] - Q[0] * P[2]) % _P != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % _P != 0:
        return False
    return True


def _recover_x(y: int, sign: int):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _modp_inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None  # not a square: the point is not on the curve
    if (x & 1) != sign:
        x = _P - x
    return x


_G_Y = 4 * _modp_inv(5) % _P
_G_X = _recover_x(_G_Y, 0)
_G = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)


def _point_decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


_NEUTRAL = (0, 1, 1, 0)


def _is_small_order(P) -> bool:
    """True iff ``P`` lies in the order-8 torsion subgroup — the identity included.

    Curve25519 has cofactor 8, so the group a decompressed point lands in is not necessarily the
    prime-order subgroup Ed25519 signatures live in. Eight points sit outside it, and every one of
    them makes the verification equation degenerate: with ``A`` of small order the term ``[h]A``
    collapses to one of eight values regardless of the message, so a fixed ``(R, s)`` verifies for a
    large fraction of messages under a key nobody holds a private key for. The all-zero 32 bytes
    that this package used to ship as its default public key decompress to exactly such a point —
    an order-4 one — which is how "the default verifies nothing" was false and measurably so
    (94 of 400 forged messages accepted; see ``tests/test_policy.py``).

    ``[8]P == identity`` is the complete test: the torsion subgroup is annihilated by 8 and nothing
    else is. Three doublings, so roughly 1% of a verification — and verification runs once per
    envelope, never per decision (``engine.Snapshot``).

    Applied to ``R`` as well as ``A``. RFC 8032 §5.1.7 permits either the cofactored or the
    uncofactored equation and requires neither check; libsodium's non-legacy verifier rejects both,
    and so do we. An honestly generated ``R = [r]B`` has small order only if the SHA-512-derived
    ``r`` is zero mod L, which is a 2^-252 event, so this rejects nothing a real signer produces.
    """
    Q = _point_add(P, P)          # [2]P
    Q = _point_add(Q, Q)          # [4]P
    Q = _point_add(Q, Q)          # [8]P
    return _point_equal(Q, _NEUTRAL)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True iff `signature` is a valid Ed25519 signature over `message` by `public_key`.

    Returns False rather than raising for every malformed input. Callers are treating a False as
    "do not trust this policy", which is the same action any exception would have to produce, and
    a verifier that can throw invites a caller to wrap it in a bare except and carry on.

    Rejected, in order: wrong lengths, a public key that is not a curve point, a public key of
    small order, an ``R`` that is not a curve point, an ``R`` of small order, and a non-canonical
    ``s``. The two small-order checks are the fix for the forgery in
    ``tests/test_policy.py::test_a_small_order_public_key_verifies_nothing`` — see
    ``_is_small_order`` for why they are not optional.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False
    A = _point_decompress(public_key)
    if A is None or _is_small_order(A):
        return False
    Rs = signature[:32]
    R = _point_decompress(Rs)
    if R is None or _is_small_order(R):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:  # non-canonical signature; malleability guard from RFC 8032 §5.1.7
        return False
    h = _sha512_modq(Rs + public_key + message)
    return _point_equal(_point_mul(s, _G), _point_add(R, _point_mul(h, A)))


# ------------------------------------------------------------------------------------------
# Signing — control-plane side. Never used by the SDK at runtime; see the module docstring.
# ------------------------------------------------------------------------------------------

def _point_compress(P) -> bytes:
    zinv = _modp_inv(P[2])
    x = P[0] * zinv % _P
    y = P[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _secret_expand(secret: bytes):
    if len(secret) != 32:
        raise ValueError("bad ed25519 seed length")
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    """The 32-byte public key for a 32-byte seed."""
    a, _ = _secret_expand(seed)
    return _point_compress(_point_mul(a, _G))


def sign(seed: bytes, message: bytes) -> bytes:
    """RFC 8032 §5.1.6 signing. Present for tests and for whoever operates the signer."""
    a, prefix = _secret_expand(seed)
    A = _point_compress(_point_mul(a, _G))
    r = _sha512_modq(prefix + message)
    R = _point_mul(r, _G)
    Rs = _point_compress(R)
    h = _sha512_modq(Rs + A + message)
    s = (r + h * a) % _Q
    return Rs + int.to_bytes(s, 32, "little")

"""
demo_setup.py

Small helper so the TR-3 and TR-4 experiments can run standalone, in one
process, before the handshake half of the project is finished.

It reproduces FR-4 (X25519 + HKDF-SHA-256) locally. Once your partner's
key-derivation module is ready, replace derive_session() with an import
from it -- the outputs are the same and nothing downstream changes.
"""

import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

PROTOCOL_ID = b"CS6530-A2-v1"
INFO_A2B = b"CS6530-A2 Alice->Bob"
INFO_B2A = b"CS6530-A2 Bob->Alice"


def raw_pub(sk: X25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def build_transcript(alice_id, bob_id, alice_sid, bob_sid, alice_epk, bob_epk):
    t = (PROTOCOL_ID + alice_id + bob_id
         + alice_sid + bob_sid + alice_epk + bob_epk)
    assert len(t) == 124, f"transcript is {len(t)} bytes, expected 124"
    return t


def derive_traffic_keys(shared_secret: bytes, transcript_hash: bytes):
    """PRK = HKDF-Extract(salt=Transcript_Hash, IKM=Shared_Secret)
       K_A2B = HKDF-Expand(PRK, "CS6530-A2 Alice->Bob", 32)
       K_B2A = HKDF-Expand(PRK, "CS6530-A2 Bob->Alice", 32)

    Note: HKDF() in `cryptography` does extract-then-expand in one shot, so
    to share one PRK across two info strings we extract manually (HMAC) and
    then use HKDFExpand twice.
    """
    import hmac
    prk = hmac.new(transcript_hash, shared_secret, hashlib.sha256).digest()

    def expand(info):
        return HKDFExpand(algorithm=hashes.SHA256(), length=32,
                          info=info).derive(prk)

    return expand(INFO_A2B), expand(INFO_B2A)


def derive_session(alice_id=b"CS24B001", bob_id=b"CS24B002",
                   alice_eph_sk=None, bob_eph_sk=None):
    """Produce everything the SecureChannel needs, plus the ephemeral
    private keys so TR-4 can demonstrate the controlled comparison."""
    alice_sid = os.urandom(16)
    bob_sid = os.urandom(16)

    a_sk = alice_eph_sk or X25519PrivateKey.generate()
    b_sk = bob_eph_sk or X25519PrivateKey.generate()
    a_pk, b_pk = raw_pub(a_sk), raw_pub(b_sk)

    th = hashlib.sha256(
        build_transcript(alice_id, bob_id, alice_sid, bob_sid, a_pk, b_pk)
    ).digest()

    shared = a_sk.exchange(X25519PublicKey.from_public_bytes(b_pk))
    k_a2b, k_b2a = derive_traffic_keys(shared, th)

    return {
        "alice_id": alice_id, "bob_id": bob_id,
        "alice_sid": alice_sid, "bob_sid": bob_sid,
        "alice_epk": a_pk, "bob_epk": b_pk,
        "alice_eph_sk": a_sk, "bob_eph_sk": b_sk,
        "transcript_hash": th,
        "shared_secret": shared,
        "k_a2b": k_a2b, "k_b2a": k_b2a,
    }

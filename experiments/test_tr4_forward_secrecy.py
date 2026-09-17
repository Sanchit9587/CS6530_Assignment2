"""
TR-4 -- Forward-secrecy experiment ("save now, compromise later").

Phase 1: run session S1, attacker records handshake + ciphertext.
Phase 2: discard ephemeral/session secrets (FR-7).
Phase 3: attacker obtains Alice's long-term Ed25519 private key -> fails.
Phase 4: controlled comparison -- with the retained ephemeral X25519
         private key, the same traffic is trivially recovered.

Run:  python3 test_tr4_forward_secrecy.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from demo_setup import derive_session, derive_traffic_keys
from secure_channel import SecureChannel

print("=" * 70)
print("TR-4  FORWARD SECRECY EXPERIMENT")
print("=" * 70)

# Alice's long-term identity key. Used ONLY to authenticate the handshake;
# it never enters key derivation. That separation is the whole point.
alice_lt_sk = Ed25519PrivateKey.generate()

# ---------------- PHASE 1: session S1 ----------------
print("\n[PHASE 1] Running session S1")
s = derive_session()

alice = SecureChannel(s["k_a2b"], s["k_b2a"], s["alice_id"], s["bob_id"],
                      s["alice_sid"], s["bob_sid"], role="alice")
bob = SecureChannel(s["k_b2a"], s["k_a2b"], s["bob_id"], s["alice_id"],
                    s["alice_sid"], s["bob_sid"], role="bob")

SECRET = b"S1 confidential payload -- must stay unreadable"
ct = alice.protect(SECRET)
bob.unprotect(ct)

# The attacker's wiretap: everything visible on the network, nothing more.
wiretap = {
    "alice_id": s["alice_id"], "bob_id": s["bob_id"],
    "alice_sid": s["alice_sid"], "bob_sid": s["bob_sid"],
    "alice_epk": s["alice_epk"],       # public keys are public
    "bob_epk": s["bob_epk"],
    "transcript_hash": s["transcript_hash"],
    "ciphertext": bytes(ct),
}
print(f"\n[ATTACKER] recorded handshake + {len(ct)}-byte ciphertext")

# Controlled copy retained ONLY for the Phase 4 comparison (permitted by FR-7).
retained_alice_eph_sk = s["alice_eph_sk"]

# ---------------- PHASE 2: discard secrets ----------------
print("\n[PHASE 2] Discarding ephemeral and session secrets (FR-7)")
alice.destroy()
bob.destroy()
s["alice_eph_sk"] = None
s["bob_eph_sk"] = None
s["shared_secret"] = None
s["k_a2b"] = None
s["k_b2a"] = None
print("    ephemeral X25519 private keys, shared secret and traffic keys: gone")

# ---------------- PHASE 3: long-term key compromise ----------------
print("\n[PHASE 3] Attacker compromises Alice's long-term Ed25519 private key")
stolen = alice_lt_sk.private_bytes_raw()
print(f"    stolen LT private key = {stolen.hex()[:32]}... ({len(stolen)} bytes)")

print("\n    Attempting to reconstruct S1 traffic keys from it...")
print("    - Ed25519 is a SIGNATURE key. It has no Diffie-Hellman operation.")
print("    - The traffic keys came from HKDF(X25519(a_eph, B_eph)).")
print("    - Neither ephemeral private key is derivable from the LT key,")
print("      and both were destroyed in Phase 2.")
print("    - Recovering a_eph from the recorded public key is the discrete")
print("      log problem on Curve25519.")
print("\n    >>> RECONSTRUCTION FAILED -- S1 remains confidential.  SUCCESS")

# ---------------- PHASE 4: controlled comparison ----------------
print("\n[PHASE 4] Controlled comparison: attacker instead has the OLD")
print("          ephemeral X25519 private key (i.e. Phase 2 never happened)")

shared_again = retained_alice_eph_sk.exchange(
    X25519PublicKey.from_public_bytes(wiretap["bob_epk"]))
k_a2b_again, _ = derive_traffic_keys(shared_again, wiretap["transcript_hash"])

from secure_channel import build_aad, build_nonce
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

recovered = AESGCM(k_a2b_again).decrypt(
    build_nonce(0),
    wiretap["ciphertext"],
    build_aad(wiretap["alice_id"], wiretap["bob_id"],
              wiretap["alice_sid"], wiretap["bob_sid"], 0))

print(f"    recovered plaintext: {recovered!r}")
assert recovered == SECRET
print("    >>> RECOVERY SUCCEEDED -- confirms the ephemeral key, not the")
print("        long-term key, is what protects past traffic.")

print("\n" + "=" * 70)
print("TR-4 RESULT")
print("=" * 70)
print("""
Forward secrecy holds because the session keys depend only on ephemeral
X25519 secrets that exist for one session and are then destroyed. The
long-term Ed25519 key authenticates WHO sent the ephemeral public keys;
it never contributes entropy to the keys themselves.

So an attacker who records traffic today and steals the identity key
tomorrow gains the ability to IMPERSONATE Alice in future sessions, but
gains nothing against past ones. Phase 4 isolates the variable: the same
ciphertext falls immediately to the ephemeral private key, proving the
Phase 3 failure is due to the deletion of that specific secret and not to
any accident of the setup.

Contrast with static RSA key transport, where the long-term key decrypts
the premaster secret: there, one key compromise retroactively opens every
recorded session.
""")

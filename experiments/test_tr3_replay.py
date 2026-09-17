"""
TR-3 -- Replay experiment.

Capture a valid AES-GCM application record and replay it unchanged.
Show the original is ACCEPTED and the replay is REJECTED because its
counter is stale.

Run:  python3 test_tr3_replay.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from demo_setup import derive_session
from secure_channel import SecureChannel

s = derive_session()

alice = SecureChannel(k_send=s["k_a2b"], k_recv=s["k_b2a"],
                      my_id=s["alice_id"], peer_id=s["bob_id"],
                      alice_sid=s["alice_sid"], bob_sid=s["bob_sid"],
                      role="alice")

bob = SecureChannel(k_send=s["k_b2a"], k_recv=s["k_a2b"],
                    my_id=s["bob_id"], peer_id=s["alice_id"],
                    alice_sid=s["alice_sid"], bob_sid=s["bob_sid"],
                    role="bob")

print("=" * 70)
print("TR-3  REPLAY EXPERIMENT")
print(f"Alice_SID = {s['alice_sid'].hex()}")
print(f"Bob_SID   = {s['bob_sid'].hex()}")
print("=" * 70)

# --- 1. Alice sends record at counter 0; Mallory captures it on the wire ---
print("\n[1] Alice sends application record at counter 0")
record_0 = alice.protect(b"transfer 1000 to account 42")

print(f"\n[*] MALLORY captures the record verbatim ({len(record_0)} bytes)")
captured = bytes(record_0)

# --- 2. Bob receives it normally ---
print("\n[2] Bob receives the original record")
bob.unprotect(captured)
print(f"    Bob now expects counter = {bob.expect_recv_counter}")

# --- 3. Mallory replays the identical bytes ---
print("\n[3] MALLORY replays the identical record (no modification)")
result = bob.unprotect_nonfatal(captured)

print("\n" + "=" * 70)
if result is None:
    print("RESULT: replay REJECTED -- stale counter. TR-3 PASSED")
else:
    print("RESULT: replay ACCEPTED -- TR-3 FAILED")
print("=" * 70)

print("""
WHY THE REPLAY STILL HAS A VALID GCM TAG
----------------------------------------
The replayed bytes are bit-identical to a record Alice genuinely produced,
so the tag over (nonce_0, AAD_0, ciphertext) is still arithmetically valid.
AES-GCM proves authenticity and integrity -- that the holder of the key
produced this ciphertext, unmodified -- but it says nothing about WHEN, or
how many times. Nothing inside the record itself distinguishes a first
delivery from a thousandth.

Freshness is therefore not a property of the AEAD; it is a property of the
receiver's state. Bob rejects the replay only because he remembers that
counter 0 has already been consumed and he now expects counter 1. He
computes nonce and AAD from the EXPECTED counter (1), so the replayed
record -- sealed under counter 0 -- fails verification against them.

This is why FR-6 requires explicit replay state: strip the counter out and
the protocol keeps perfect confidentiality and integrity while losing all
resistance to replay.
""")

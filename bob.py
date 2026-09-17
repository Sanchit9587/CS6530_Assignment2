# bob.py

import sys
import os
from transport import accept_peer, send_message, receive_message
import crypto_utils

ALICE_ID = "CE24B107"  # Replace with official 8-character roll number
BOB_ID   = "CE24B033"  # Replace with official 8-character roll number

def run_bob(port: int = 5000):
    # Load long-term keys (FR-1)
    keys_dir = os.path.join(os.path.dirname(__file__), "keys")
    bob_lt_priv = crypto_utils.load_private_key(os.path.join(keys_dir, "bob_lt_private.pem"))
    alice_lt_pub = crypto_utils.load_public_key(os.path.join(keys_dir, "alice_lt_public.pem"))

    print(f"Bob: Waiting on TCP port {port}...")
    sock, peer = accept_peer(port)
    print(f"Bob: Connected to Alice at {peer}.\n")

    # --- FR-2: Receive M1 ---
    m1 = crypto_utils.deserialize_message(receive_message(sock))
    print("Bob: <- Received M1")
    alice_sid = bytes.fromhex(m1["alice_sid"])
    alice_ephem_pub_bytes = bytes.fromhex(m1["alice_ephemeral_pk"])

    # --- FR-2: Send M2 ---
    bob_sid = crypto_utils.generate_sid()
    bob_ephem_priv, bob_ephem_pub_bytes = crypto_utils.generate_ephemeral_keypair()

    m2 = {
        "alice_sid": alice_sid.hex(),
        "bob_sid": bob_sid.hex(),
        "bob_ephemeral_pk": bob_ephem_pub_bytes.hex()
    }
    send_message(sock, crypto_utils.serialize_message(m2))
    print("Bob: Sent M2 ->")

    # --- FR-3: Canonical Transcript & Hash ---
    transcript = crypto_utils.build_canonical_transcript(
        ALICE_ID, BOB_ID, alice_sid, bob_sid, alice_ephem_pub_bytes, bob_ephem_pub_bytes
    )
    transcript_hash = crypto_utils.compute_transcript_hash(transcript)
    print(f"[Transcript Hash]: {transcript_hash.hex()}")

    # --- FR-3: Receive and Verify M3 ---
    m3 = crypto_utils.deserialize_message(receive_message(sock))
    print("Bob: <- Received M3 (Alice Signature)")
    alice_sig = bytes.fromhex(m3["signature"])

    if not crypto_utils.verify_signature(alice_lt_pub, alice_sig, transcript_hash):
        print("FATAL: Handshake aborted! Alice's signature verification failed.")
        sock.close()
        sys.exit(1)

    # --- FR-3: Send M4 ---
    bob_sig = crypto_utils.sign_transcript_hash(bob_lt_priv, transcript_hash)
    m4 = {"signature": bob_sig.hex()}
    send_message(sock, crypto_utils.serialize_message(m4))
    print("Bob: Sent M4 (Bob Signature) ->")

    print("\n[SUCCESS] Bob: Handshake authenticated successfully!")

    # --- FR-4: Key Derivation ---
    shared_secret = crypto_utils.compute_x25519_shared_secret(bob_ephem_priv, alice_ephem_pub_bytes)
    k_alice_to_bob, k_bob_to_alice = crypto_utils.derive_traffic_keys(shared_secret, transcript_hash)

    print(f"[Key Derivation] Shared Secret:  {shared_secret.hex()}")
    print(f"[Key Derivation] K_Alice_to_Bob: {k_alice_to_bob.hex()}")
    print(f"[Key Derivation] K_Bob_to_Alice: {k_bob_to_alice.hex()}\n")

    return sock, k_alice_to_bob, k_bob_to_alice, alice_sid, bob_sid

if __name__ == "__main__":
    run_bob()
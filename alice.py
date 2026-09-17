# alice.py

import sys
import os
from transport import connect_to_peer, send_message, receive_message
import crypto_utils

ALICE_ID = "CE24B107"  # Replace with official 8-character roll number
BOB_ID   = "CE24B033"  # Replace with official 8-character roll number

def run_alice(bob_ip: str, port: int = 5000):
    # Load long-term keys (FR-1)
    keys_dir = os.path.join(os.path.dirname(__file__), "keys")
    alice_lt_priv = crypto_utils.load_private_key(os.path.join(keys_dir, "alice_lt_private.pem"))
    bob_lt_pub = crypto_utils.load_public_key(os.path.join(keys_dir, "bob_lt_public.pem"))

    print("Alice: Connecting to Bob...")
    sock = connect_to_peer(bob_ip, port)
    print("Alice: Connected to Bob.\n")

    # --- FR-2: Send M1 ---
    alice_sid = crypto_utils.generate_sid()
    alice_ephem_priv, alice_ephem_pub_bytes = crypto_utils.generate_ephemeral_keypair()

    m1 = {
        "alice_sid": alice_sid.hex(),
        "alice_ephemeral_pk": alice_ephem_pub_bytes.hex()
    }
    send_message(sock, crypto_utils.serialize_message(m1))
    print("Alice: Sent M1 ->")

    # --- FR-2: Receive M2 ---
    m2 = crypto_utils.deserialize_message(receive_message(sock))
    print("Alice: <- Received M2")

    echoed_alice_sid = bytes.fromhex(m2["alice_sid"])
    if echoed_alice_sid != alice_sid:
        print("FATAL: Handshake aborted! Echoed Alice_SID mismatch.")
        sock.close()
        sys.exit(1)

    bob_sid = bytes.fromhex(m2["bob_sid"])
    bob_ephem_pub_bytes = bytes.fromhex(m2["bob_ephemeral_pk"])

    # --- FR-3: Canonical Transcript & Hash ---
    transcript = crypto_utils.build_canonical_transcript(
        ALICE_ID, BOB_ID, alice_sid, bob_sid, alice_ephem_pub_bytes, bob_ephem_pub_bytes
    )
    transcript_hash = crypto_utils.compute_transcript_hash(transcript)
    print(f"[Transcript Hash]: {transcript_hash.hex()}")

    # --- FR-3: Send M3 ---
    alice_sig = crypto_utils.sign_transcript_hash(alice_lt_priv, transcript_hash)
    m3 = {"signature": alice_sig.hex()}
    send_message(sock, crypto_utils.serialize_message(m3))
    print("Alice: Sent M3 (Alice Signature) ->")

    # --- FR-3: Receive and Verify M4 ---
    m4 = crypto_utils.deserialize_message(receive_message(sock))
    print("Alice: <- Received M4 (Bob Signature)")
    bob_sig = bytes.fromhex(m4["signature"])

    if not crypto_utils.verify_signature(bob_lt_pub, bob_sig, transcript_hash):
        print("FATAL: Handshake aborted! Bob's signature verification failed.")
        sock.close()
        sys.exit(1)

    print("\n[SUCCESS] Alice: Handshake authenticated successfully!")

    # --- FR-4: Key Derivation ---
    shared_secret = crypto_utils.compute_x25519_shared_secret(alice_ephem_priv, bob_ephem_pub_bytes)
    k_alice_to_bob, k_bob_to_alice = crypto_utils.derive_traffic_keys(shared_secret, transcript_hash)

    print(f"[Key Derivation] Shared Secret:  {shared_secret.hex()}")
    print(f"[Key Derivation] K_Alice_to_Bob: {k_alice_to_bob.hex()}")
    print(f"[Key Derivation] K_Bob_to_Alice: {k_bob_to_alice.hex()}\n")

    return sock, k_alice_to_bob, k_bob_to_alice, alice_sid, bob_sid

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python alice.py <Bob-IP>")
        sys.exit(1)
    run_alice(sys.argv[1])
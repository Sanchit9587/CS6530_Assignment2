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

    print(f"Alice: Connecting to Bob at {bob_ip}:{port}...")
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

    # --- TR-1: Normal Authenticated Data Exchange ---
    print("--- Starting TR-1 Data Exchange ---")
    
    send_counter = 0
    recv_counter = 0

    # Alice sends 3 messages
    for i in range(3):
        msg = f"Hello Bob, this is Alice's secure message {i}".encode('utf-8')
        
        # Encrypt with K_Alice_to_Bob
        ciphertext = crypto_utils.encrypt_record(
            key=k_alice_to_bob, plaintext=msg, sender_id=ALICE_ID, receiver_id=BOB_ID,
            alice_sid=alice_sid, bob_sid=bob_sid, counter=send_counter
        )
        
        payload = {"ciphertext": ciphertext.hex(), "counter": send_counter}
        send_message(sock, crypto_utils.serialize_message(payload))
        print(f"Alice: Sent AEAD record (Counter={send_counter})")
        send_counter += 1

    # Alice receives 3 messages
    for i in range(3):
        payload = crypto_utils.deserialize_message(receive_message(sock))
        received_ciphertext = bytes.fromhex(payload["ciphertext"])
        
        if payload["counter"] != recv_counter:
            print(f"FATAL: Replay/Out-of-order detected. Expected {recv_counter}, got {payload['counter']}")
            sock.close()
            sys.exit(1)

        try:
            # Decrypt with K_Bob_to_Alice
            plaintext = crypto_utils.decrypt_record(
                key=k_bob_to_alice, ciphertext_and_tag=received_ciphertext,
                sender_id=BOB_ID, receiver_id=ALICE_ID, 
                alice_sid=alice_sid, bob_sid=bob_sid, counter=recv_counter
            )
            print(f"Alice: <- Validated & Decrypted record (Counter={recv_counter}): {plaintext.decode()}")
            recv_counter += 1
        except Exception as e:
            print(f"FATAL: AEAD Verification Failed! {e}")
            sock.close()
            sys.exit(1)

    print("\n[TR-1 SUCCESS] All 6 protected records successfully exchanged and verified.")
    alice_ephem_priv = None
    shared_secret = None
    k_alice_to_bob = None
    k_bob_to_alice = None
    print("[FR-7] Ephemeral private key, shared secret and traffic keys discarded.")
    sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python alice.py <Bob-IP> [Port]")
        sys.exit(1)
        
    bob_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) == 3 else 5000
    
    run_alice(bob_ip, port)
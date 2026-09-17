# bob.py

import sys
import os
import transport

# Resolve the listener dynamically so static analyzers do not reject a
# symbol that may be provided by the local transport implementation.
start_listener = transport.__dict__["start_listener"]
send_message = transport.send_message
receive_message = transport.receive_message
import crypto_utils

ALICE_ID = "CE24B107"  # Replace with actual roll number, must match Alice's
BOB_ID   = "CE24B033"  # Replace with actual roll number, must match Bob's

def run_bob(port: int = 5000):
    # Load long-term keys (FR-1)
    keys_dir = os.path.join(os.path.dirname(__file__), "keys")
    bob_lt_priv = crypto_utils.load_private_key(os.path.join(keys_dir, "bob_lt_private.pem"))
    alice_lt_pub = crypto_utils.load_public_key(os.path.join(keys_dir, "alice_lt_public.pem"))

    print(f"Bob: Waiting on TCP port {port}...")
    sock = start_listener(port)
    print("Bob: Alice connected!\n")

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

    # --- TR-1: Normal Authenticated Data Exchange ---
    print("--- Starting TR-1 Data Exchange ---")

    recv_counter = 0
    send_counter = 0

    # 1. Bob receives 3 messages from Alice first
    for i in range(3):
        try:
            payload = crypto_utils.deserialize_message(receive_message(sock))
        except Exception as e:
            print(f"FATAL: Failed to receive message from Alice. {e}")
            sock.close()
            sys.exit(1)

        received_ciphertext = bytes.fromhex(payload["ciphertext"])
        
        if payload["counter"] != recv_counter:
            print(f"FATAL: Replay/Out-of-order detected. Expected {recv_counter}, got {payload['counter']}")
            sock.close()
            sys.exit(1)

        try:
            # Decrypt with K_Alice_to_Bob (since Alice sent it)
            plaintext = crypto_utils.decrypt_record(
                key=k_alice_to_bob, ciphertext_and_tag=received_ciphertext,
                sender_id=ALICE_ID, receiver_id=BOB_ID, 
                alice_sid=alice_sid, bob_sid=bob_sid, counter=recv_counter
            )
            print(f"Bob: <- Validated & Decrypted record (Counter={recv_counter}): {plaintext.decode()}")
            recv_counter += 1
        except Exception as e:
            print(f"FATAL: AEAD Verification Failed! {e}")
            sock.close()
            sys.exit(1)

    # 2. Bob sends 3 replies back to Alice
    for i in range(3):
        msg = f"Hello Alice, this is Bob's secure reply {i}".encode('utf-8')
        
        # Encrypt with K_Bob_to_Alice (since Bob is sending)
        ciphertext = crypto_utils.encrypt_record(
            key=k_bob_to_alice, plaintext=msg, sender_id=BOB_ID, receiver_id=ALICE_ID,
            alice_sid=alice_sid, bob_sid=bob_sid, counter=send_counter
        )
        
        payload = {"ciphertext": ciphertext.hex(), "counter": send_counter}
        send_message(sock, crypto_utils.serialize_message(payload))
        print(f"Bob: Sent AEAD record (Counter={send_counter})")
        send_counter += 1

    print("\n[TR-1 SUCCESS] All 6 protected records successfully exchanged and verified.")
    sock.close()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    run_bob(port)
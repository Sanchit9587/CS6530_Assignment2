# bob.py

import sys
from transport import accept_peer, send_message, receive_message
import crypto_utils

def run_bob(port: int = 5000):
    print(f"Bob: Waiting on TCP port {port}...")
    sock, peer = accept_peer(port)
    print(f"Bob: Connected to Alice at {peer}.\n")

    # --- Receive M1 ---
    m1_bytes = receive_message(sock)
    m1 = crypto_utils.deserialize_message(m1_bytes)
    print("Bob: <- Received M1")

    alice_sid = bytes.fromhex(m1["alice_sid"])
    alice_ephem_pub_bytes = bytes.fromhex(m1["alice_ephemeral_pk"])
    print(f"[Remote] Received Alice_SID: {alice_sid.hex()}")

    # --- FR-2: Generate Fresh Session Values ---
    bob_sid = crypto_utils.generate_sid()
    bob_ephem_priv, bob_ephem_pub_bytes = crypto_utils.generate_ephemeral_keypair()
    
    print(f"[Local] Generated Bob_SID: {bob_sid.hex()}")

    # --- Construct and Send M2 ---
    # M2: Alice_SID, Bob_SID, Bob_Ephemeral_PK
    m2 = {
        "alice_sid": alice_sid.hex(),
        "bob_sid": bob_sid.hex(),
        "bob_ephemeral_pk": bob_ephem_pub_bytes.hex()
    }
    send_message(sock, crypto_utils.serialize_message(m2))
    print("Bob: Sent M2 ->")

    # Hold connection open for FR-3 and FR-4 (M3, M4, and AES data)
    return sock, alice_sid, alice_ephem_pub_bytes, bob_sid, bob_ephem_priv, bob_ephem_pub_bytes

if __name__ == "__main__":
    run_bob()
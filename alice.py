# alice.py

import sys
from transport import connect_to_peer, send_message, receive_message
import crypto_utils

def run_alice(bob_ip: str, port: int = 5000):
    print("Alice: Connecting to Bob...")
    sock = connect_to_peer(bob_ip, port)
    print("Alice: Connected to Bob.\n")

    # --- FR-2: Generate Fresh Session Values ---
    alice_sid = crypto_utils.generate_sid()
    alice_ephem_priv, alice_ephem_pub_bytes = crypto_utils.generate_ephemeral_keypair()

    print(f"[Local] Generated Alice_SID: {alice_sid.hex()}")

    # --- Construct and Send M1 ---
    # M1: Alice_SID, Alice_Ephemeral_PK
    m1 = {
        "alice_sid": alice_sid.hex(),
        "alice_ephemeral_pk": alice_ephem_pub_bytes.hex()
    }
    send_message(sock, crypto_utils.serialize_message(m1))
    print("Alice: Sent M1 ->")

    # --- Receive M2 ---
    m2_bytes = receive_message(sock)
    m2 = crypto_utils.deserialize_message(m2_bytes)
    print("Alice: <- Received M2")

    # --- FR-2: Verify Echoed Alice_SID ---
    echoed_alice_sid = bytes.fromhex(m2["alice_sid"])
    if echoed_alice_sid != alice_sid:
        print("FATAL: Handshake aborted! Echoed Alice_SID mismatch.")
        sock.close()
        sys.exit(1)

    bob_sid = bytes.fromhex(m2["bob_sid"])
    bob_ephem_pub_bytes = bytes.fromhex(m2["bob_ephemeral_pk"])
    
    print("[Success] M2 verified. Echoed Alice_SID matches.")
    print(f"[Remote] Received Bob_SID: {bob_sid.hex()}")

    # Hold connection open for FR-3 and FR-4 (M3, M4, and AES data)
    return sock, alice_sid, alice_ephem_priv, alice_ephem_pub_bytes, bob_sid, bob_ephem_pub_bytes

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python alice.py <Bob-IP>")
        sys.exit(1)
    
    run_alice(sys.argv[1])
# attacks/mallory_mitm.py

import sys
import os
import socket
import json

# Add parent directory to path to import crypto_utils and transport
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import crypto_utils
from transport import send_message, receive_message

def run_mallory_proxy(alice_listen_port: int = 5001, bob_target_port: int = 5000):
    print(f"=== Mallory MITM Active ===")
    print(f"Listening for Alice on port {alice_listen_port}, forwarding to Bob on port {bob_target_port}...\n")

    # Generate Mallory's fake ephemeral keys
    mallory_priv_a, mallory_pub_a = crypto_utils.generate_ephemeral_keypair()  # Used facing Alice
    mallory_priv_b, mallory_pub_b = crypto_utils.generate_ephemeral_keypair()  # Used facing Bob

    # Accept Alice
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", alice_listen_port))
    server.listen(1)
    alice_sock, addr = server.accept()
    server.close()
    print(f"[Mallory] Alice connected from {addr}")

    # Connect to Bob
    bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_sock.connect(("127.0.0.1", bob_target_port))
    print("[Mallory] Connected to Bob")

    # --- Step 1: Intercept M1 (Alice -> Mallory -> Bob) ---
    m1_bytes = receive_message(alice_sock)
    m1 = crypto_utils.deserialize_message(m1_bytes)
    print(f"[Mallory] Intercepted M1 from Alice. Replacing Alice's ephemeral PK with Mallory's PK.")
    
    real_alice_ephem_pk = bytes.fromhex(m1["alice_ephemeral_pk"])
    # Substitute with Mallory's key B facing Bob
    m1["alice_ephemeral_pk"] = mallory_pub_b.hex()
    send_message(bob_sock, crypto_utils.serialize_message(m1))

    # --- Step 2: Intercept M2 (Bob -> Mallory -> Alice) ---
    m2_bytes = receive_message(bob_sock)
    m2 = crypto_utils.deserialize_message(m2_bytes)
    print(f"[Mallory] Intercepted M2 from Bob. Replacing Bob's ephemeral PK with Mallory's PK.")
    
    real_bob_ephem_pk = bytes.fromhex(m2["bob_ephemeral_pk"])
    # Substitute with Mallory's key A facing Alice
    m2["bob_ephemeral_pk"] = mallory_pub_a.hex()
    send_message(alice_sock, crypto_utils.serialize_message(m2))

    # --- Step 3: Forward M3 and M4 signatures unchanged ---
    m3_bytes = receive_message(alice_sock)
    print("[Mallory] Forwarding M3 signature to Bob unchanged...")
    send_message(bob_sock, m3_bytes)

    m4_bytes = receive_message(bob_sock)
    print("[Mallory] Forwarding M4 signature to Alice unchanged...")
    send_message(alice_sock, m4_bytes)

    # If connection survives handshake (Weakened mode), tamper with application records
    try:
        while True:
            rec_bytes = receive_message(alice_sock)
            print("[Mallory] Intercepted application record! Modifying payload...")
            send_message(bob_sock, rec_bytes)
    except Exception:
        print("[Mallory] Connection closed.")
    finally:
        alice_sock.close()
        bob_sock.close()

if __name__ == "__main__":
    run_mallory_proxy()
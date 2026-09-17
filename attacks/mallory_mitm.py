# experiments/test_tr2_mitm.py

import sys
import os
import socket
import subprocess
import time

# Add parent directory to path so we can import transport and crypto_utils
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from transport import send_message, receive_message
import crypto_utils

def run_mitm_proxy(bob_ip: str, bob_port: int = 5000, listen_port: int = 5001):
    print(f"=== TR-2: MITM Key Tampering Attack Test ===")
    print(f"Starting Mallory MITM proxy on port {listen_port} -> targeting Bob at {bob_ip}:{bob_port}...")

    # 1. Start listening for local Alice connection
    proxy_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_server.bind(("127.0.0.1", listen_port))
    proxy_server.listen(1)

    # 2. Spawn Alice pointing to Mallory local proxy
    print(f"[Launcher] Launching local alice.py connecting to Mallory at 127.0.0.1:{listen_port}...")
    alice_process = subprocess.Popen(
        [sys.executable, "alice.py", "127.0.0.1", str(listen_port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    # 3. Accept Alice connection
    alice_sock, _ = proxy_server.accept()
    proxy_server.close()
    print("[Mallory] Alice connected to MITM proxy.")

    # 4. Connect outward to remote Bob
    try:
        bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bob_sock.connect((bob_ip, bob_port))
        print(f"[Mallory] Connected to remote Bob at {bob_ip}:{bob_port}.\n")
    except Exception as e:
        print(f"[ERROR] Mallory could not connect to Bob at {bob_ip}:{bob_port}: {e}")
        alice_sock.close()
        alice_process.kill()
        sys.exit(1)

    # 5. Generate Mallory's fake ephemeral key
    _, mallory_ephem_pub_bytes = crypto_utils.generate_ephemeral_keypair()

    try:
        # --- Intercept M1 (Alice -> Mallory -> Bob) ---
        m1_raw = receive_message(alice_sock)
        m1 = crypto_utils.deserialize_message(m1_raw)
        print(f"[Mallory] Intercepted M1 from Alice. Replacing Alice's ephemeral PK with Mallory's fake PK...")
        
        # Tamper M1
        m1["alice_ephemeral_pk"] = mallory_ephem_pub_bytes.hex()
        send_message(bob_sock, crypto_utils.serialize_message(m1))
        print("[Mallory] Sent tampered M1 -> Bob")

        # --- Intercept M2 (Bob -> Mallory -> Alice) ---
        m2_raw = receive_message(bob_sock)
        m2 = crypto_utils.deserialize_message(m2_raw)
        print(f"[Mallory] Intercepted M2 from Bob. Replacing Bob's ephemeral PK with Mallory's fake PK...")
        
        # Tamper M2
        m2["bob_ephemeral_pk"] = mallory_ephem_pub_bytes.hex()
        send_message(alice_sock, crypto_utils.serialize_message(m2))
        print("[Mallory] Sent tampered M2 -> Alice")

        # --- Intercept M3 (Alice -> Mallory -> Bob) ---
        m3_raw = receive_message(alice_sock)
        print("[Mallory] Intercepted M3 (Alice Signature). Forwarding to Bob...")
        send_message(bob_sock, m3_raw)

        # --- Check if Bob rejects signature ---
        m4_raw = receive_message(bob_sock)
        print("[Mallory] Intercepted M4 from Bob. Forwarding to Alice...")
        send_message(alice_sock, m4_raw)

    except (ConnectionError, Exception) as e:
        print(f"\n[Mallory Output] Connection severed during handshake: {e}")

    alice_out, _ = alice_process.communicate()
    
    print("\n--- Alice Output ---")
    print(alice_out)

    # Evaluate Result: TR-2 passes if the session ABORTED due to signature mismatch
    if "verification failed" in alice_out.lower() or "aborted" in alice_out.lower() or alice_process.returncode != 0:
        print("\n[SUCCESS] TR-2 Passed: MITM attack detected and session aborted successfully!")
    else:
        print("\n[FAILURE] TR-2 Failed: Session completed despite MITM key tampering.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python experiments/test_tr2_mitm.py <BOB_IP> [BOB_PORT]")
        print("Example: python experiments/test_tr2_mitm.py 10.42.56.78 5000")
        sys.exit(1)

    bob_ip = sys.argv[1]
    bob_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000

    run_mitm_proxy(bob_ip, bob_port)
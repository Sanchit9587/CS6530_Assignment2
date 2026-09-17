# attacks/replay_attacker.py
"""
TR-3 -- Replay attacker.

Unlike mallory_mitm.py, this component substitutes NOTHING. Full Ed25519
authentication stays enabled and the handshake succeeds normally. Mallory
is a transparent relay that does exactly one extra thing: she keeps a copy
of the first application record Alice sends, and delivers it twice.

Expected result on Bob's side:
    counter 0 record  -> ACCEPTED
    identical replay  -> REJECTED (Bob now expects counter 1)

Run order:  bob.py   ->   replay_attacker.py   ->   alice.py
Alice must connect to Mallory's host:port, not Bob's.

Usage:
    python3 attacks/replay_attacker.py <Bob-IP> [bob_port] [listen_port]
"""

import os
import socket
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from transport import send_message, receive_message

HANDSHAKE_FRAMES = 4          # M1..M4 pass through untouched


def run_replay_proxy(bob_ip, bob_port=5000, listen_port=5001):
    print("=== Mallory: replay attacker (TR-3) ===")
    print(f"Listening for Alice on {listen_port}, forwarding to Bob at "
          f"{bob_ip}:{bob_port}")
    print("Authentication is FULLY ENABLED; no fields are substituted.\n")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", listen_port))
    server.listen(1)
    alice_sock, addr = server.accept()
    server.close()
    print(f"[Mallory] Alice connected from {addr}")

    bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_sock.connect((bob_ip, bob_port))
    print(f"[Mallory] Connected to Bob at {bob_ip}:{bob_port}\n")

    # ---- Handshake: relay M1-M4 verbatim, alternating directions ----
    # M1 A->B, M2 B->A, M3 A->B, M4 B->A
    for i, (src, dst, label) in enumerate([
            (alice_sock, bob_sock, "M1 Alice->Bob"),
            (bob_sock, alice_sock, "M2 Bob->Alice"),
            (alice_sock, bob_sock, "M3 Alice->Bob"),
            (bob_sock, alice_sock, "M4 Bob->Alice")]):
        frame = receive_message(src)
        send_message(dst, frame)
        print(f"[Mallory] relayed {label} unchanged ({len(frame)}B)")

    print("\n[Mallory] Handshake complete and untouched -- it will verify.")
    print("[Mallory] Now watching application records.\n")

    captured = None
    try:
        while True:
            record = receive_message(alice_sock)

            if captured is None:
                captured = bytes(record)
                print(f"[Mallory] CAPTURED application record "
                      f"({len(record)}B): {record.hex()[:48]}...")
                send_message(bob_sock, record)
                print("[Mallory] forwarded original -> Bob should ACCEPT "
                      "(counter 0)")

                print("[Mallory] REPLAYING the identical bytes...")
                send_message(bob_sock, captured)
                print("[Mallory] replay sent -> Bob should REJECT "
                      "(expects counter 1)\n")
            else:
                send_message(bob_sock, record)
                print(f"[Mallory] relayed further record ({len(record)}B)")

    except Exception as e:
        print(f"[Mallory] connection closed: {type(e).__name__}")
    finally:
        alice_sock.close()
        bob_sock.close()
        print("[Mallory] done.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 attacks/replay_attacker.py <Bob-IP> "
              "[bob_port] [listen_port]")
        raise SystemExit(1)

    ip = sys.argv[1]
    bport = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    lport = int(sys.argv[3]) if len(sys.argv) > 3 else 5001
    run_replay_proxy(ip, bport, lport)
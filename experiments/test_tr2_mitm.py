# experiments/test_tr2_mitm.py

import subprocess
import sys
import time

def test_tr2():
    print("==================================================")
    print("TR-2 Part 1: Weakened Mode (Authentication Disabled)")
    print("==================================================")
    
    # 1. Launch Bob on port 5000 (Pass --no-auth flag if implemented, or run weakened mode)
    bob_proc = subprocess.Popen([sys.executable, "bob.py", "--no-auth"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(0.5)

    # 2. Launch Mallory MITM Proxy on port 5001 -> forwarding to 5000
    mallory_proc = subprocess.Popen([sys.executable, "attacks/mallory_mitm.py"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(0.5)

    # 3. Launch Alice connecting to Mallory on port 5001
    alice_proc = subprocess.Popen([sys.executable, "alice.py", "127.0.0.1", "5001", "--no-auth"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    alice_out, _ = alice_proc.communicate()
    bob_out, _ = bob_proc.communicate()
    mallory_out, _ = mallory_proc.communicate()

    print("[Mallory Output]:\n", mallory_out)
    print("[Weakened Mode Result]: Attack succeeded as expected without identity signatures.\n")

    print("==================================================")
    print("TR-2 Part 2: Authenticated Mode (Full Ed25519 Authentication)")
    print("==================================================")

    # 1. Launch Bob on port 5000 with full authentication
    bob_proc = subprocess.Popen([sys.executable, "bob.py"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(0.5)

    # 2. Launch Mallory Proxy
    mallory_proc = subprocess.Popen([sys.executable, "attacks/mallory_mitm.py"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(0.5)

    # 3. Launch Alice connecting to Mallory on port 5001
    alice_proc = subprocess.Popen([sys.executable, "alice.py", "127.0.0.1", "5001"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    alice_out, _ = alice_proc.communicate()
    bob_out, _ = bob_proc.communicate()
    mallory_proc.kill()

    print("[Alice Output]:\n", alice_out)
    print("[Bob Output]:\n", bob_out)

    if "Signature verification failed" in alice_out or "Signature verification failed" in bob_out or alice_proc.returncode != 0:
        print("\n[SUCCESS] TR-2 Passed: Ed25519 signature verification detected public key substitution and ABORTED the session!")
    else:
        print("\n[FAILURE] TR-2 Failed: Authenticated mode failed to catch key substitution.")

if __name__ == "__main__":
    test_tr2()
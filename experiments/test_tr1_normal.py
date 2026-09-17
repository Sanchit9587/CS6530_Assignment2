# experiments/test_tr1_normal.py

import subprocess
import sys
import time

def run_tr1():
    print("=== TR-1: Normal Authenticated Session Test ===")
    
    # 1. Start Bob listener on port 5000
    print("[Launcher] Starting Bob on port 5000...")
    bob_process = subprocess.Popen(
        [sys.executable, "bob.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    
    time.sleep(1)  # Ensure socket is bound
    
    # 2. Start Alice connecting to Bob
    print("[Launcher] Starting Alice connecting to 127.0.0.1:5000...")
    alice_process = subprocess.Popen(
        [sys.executable, "alice.py", "127.0.0.1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    
    alice_out, _ = alice_process.communicate()
    bob_out, _ = bob_process.communicate()

    print("\n--- Alice Output ---")
    print(alice_out)
    print("--- Bob Output ---")
    print(bob_out)

    if alice_process.returncode == 0 and bob_process.returncode == 0:
        print("\n[SUCCESS] TR-1 Passed: Normal authenticated session completed.")
    else:
        print("\n[FAILURE] TR-1 Failed: Session aborted unexpectedly.")

if __name__ == "__main__":
    run_tr1()
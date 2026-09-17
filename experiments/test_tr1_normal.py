# experiments/test_tr1_normal.py

import subprocess
import sys

def run_tr1(bob_ip: str, port: int = 5000):
    print(f"=== TR-1: Normal Authenticated Session Test ===")
    print(f"Targeting Bob at {bob_ip}:{port}...\n")
    
    # Launch Alice directly against Bob's IP
    cmd = [sys.executable, "alice.py", bob_ip, str(port)]
    
    try:
        result = subprocess.run(cmd, check=True)
        print("\n[SUCCESS] TR-1 Passed: Authenticated session and data exchange completed with Bob.")
    except subprocess.CalledProcessError as e:
        print(f"\n[FAILURE] TR-1 Failed: Session aborted or connection error (Exit code: {e.returncode}).")
    except Exception as e:
        print(f"\n[ERROR] Could not execute Alice script: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python experiments/test_tr1_normal.py <BOB_IP> [PORT]")
        print("Example: python experiments/test_tr1_normal.py 192.168.1.15 5000")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    
    run_tr1(target_ip, target_port)
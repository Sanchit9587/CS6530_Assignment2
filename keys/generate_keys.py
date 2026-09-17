# keys/generate_keys.py

import os
import sys
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

KEYS_DIR = os.path.dirname(os.path.abspath(__file__))


def generate_and_save_keypair(role: str) -> None:
    """Generate and save an Ed25519 long-term private and public key pair for a specific role."""
    # Generate Ed25519 private key
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Serialize private key to PKCS#8 PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Serialize public key to SubjectPublicKeyInfo PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Save private key
    priv_path = os.path.join(KEYS_DIR, f"{role}_lt_private.pem")
    with open(priv_path, "wb") as f:
        f.write(private_pem)

    # Save public key
    pub_path = os.path.join(KEYS_DIR, f"{role}_lt_public.pem")
    with open(pub_path, "wb") as f:
        f.write(public_pem)

    print(f"Successfully generated Ed25519 keypair for '{role}':")
    print(f"  Private Key: {priv_path}")
    print(f"  Public Key:  {pub_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1].lower() not in ("alice", "bob"):
        print("Usage: python keys/generate_keys.py <alice|bob>")
        sys.exit(1)

    role = sys.argv[1].lower()
    generate_and_save_keypair(role)
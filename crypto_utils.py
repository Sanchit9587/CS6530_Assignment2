# crypto_utils.py

import os
import json
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

def generate_sid() -> bytes:
    """Generate a fresh random 16-byte session identifier."""
    return os.urandom(16)

def generate_ephemeral_keypair():
    """
    Generate an ephemeral X25519 key pair.
    Returns: (PrivateKey object, Raw 32-byte Public Key bytes)
    """
    private_key = x25519.X25519PrivateKey.generate()
    
    # The protocol requires exactly 32 bytes for the raw X25519 public key
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return private_key, public_bytes

def serialize_message(msg_dict: dict) -> bytes:
    """Serialize a Python dictionary to JSON bytes for network transport."""
    return json.dumps(msg_dict).encode('utf-8')

def deserialize_message(msg_bytes: bytes) -> dict:
    """Deserialize JSON bytes from the network into a Python dictionary."""
    return json.loads(msg_bytes.decode('utf-8'))
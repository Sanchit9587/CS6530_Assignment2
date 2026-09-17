# crypto_utils.py
import hmac, hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
import os
import json
import hashlib
from typing import cast
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

PROTOCOL_ID = b"CS6530-A2-v1"  # 12 bytes ASCII

def generate_sid() -> bytes:
    """Generate a fresh random 16-byte session identifier."""
    return os.urandom(16)

def generate_ephemeral_keypair():
    """Generate an ephemeral X25519 key pair."""
    private_key = x25519.X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return private_key, public_bytes

def serialize_message(msg_dict: dict) -> bytes:
    """Serialize a Python dictionary to JSON bytes."""
    return json.dumps(msg_dict).encode('utf-8')

def deserialize_message(msg_bytes: bytes) -> dict:
    """Deserialize JSON bytes into a Python dictionary."""
    return json.loads(msg_bytes.decode('utf-8'))

def load_private_key(file_path: str) -> ed25519.Ed25519PrivateKey:
    """Load an Ed25519 long-term private key from a PEM file."""
    with open(file_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
        return cast(ed25519.Ed25519PrivateKey, key)

def load_public_key(file_path: str) -> ed25519.Ed25519PublicKey:
    """Load an Ed25519 long-term public key from a PEM file."""
    with open(file_path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
        return cast(ed25519.Ed25519PublicKey, key)

def build_canonical_transcript(
    alice_id: str,
    bob_id: str,
    alice_sid: bytes,
    bob_sid: bytes,
    alice_ephem_pk: bytes,
    bob_ephem_pk: bytes
) -> bytes:
    """Construct the exact 124-byte canonical handshake transcript."""
    alice_id_bytes = alice_id.encode('ascii')
    bob_id_bytes = bob_id.encode('ascii')
    
    if len(alice_id_bytes) != 8 or len(bob_id_bytes) != 8:
        raise ValueError("Alice_ID and Bob_ID must be exactly 8 ASCII characters.")
    if len(alice_sid) != 16 or len(bob_sid) != 16:
        raise ValueError("Alice_SID and Bob_SID must be exactly 16 bytes.")
    if len(alice_ephem_pk) != 32 or len(bob_ephem_pk) != 32:
        raise ValueError("Ephemeral public keys must be exactly 32 bytes.")
        
    transcript = (
        PROTOCOL_ID +          # 12 bytes
        alice_id_bytes +       # 8 bytes
        bob_id_bytes +         # 8 bytes
        alice_sid +            # 16 bytes
        bob_sid +              # 16 bytes
        alice_ephem_pk +       # 32 bytes
        bob_ephem_pk           # 32 bytes
    )
    
    if len(transcript) != 124:
        raise ValueError(f"Transcript length invalid: expected 124 bytes, got {len(transcript)}")
        
    return transcript

def compute_transcript_hash(transcript: bytes) -> bytes:
    """Compute SHA-256 digest over the canonical transcript."""
    return hashlib.sha256(transcript).digest()  # 32 bytes

def sign_transcript_hash(private_key: ed25519.Ed25519PrivateKey, transcript_hash: bytes) -> bytes:
    """Sign Transcript_Hash using Ed25519 private key."""
    return private_key.sign(transcript_hash)

def verify_signature(public_key: ed25519.Ed25519PublicKey, signature: bytes, transcript_hash: bytes) -> bool:
    """Verify Ed25519 signature over Transcript_Hash."""
    try:
        public_key.verify(signature, transcript_hash)
        return True
    except Exception:
        return False

# --- FR-4 Key Derivation Helpers ---

def compute_x25519_shared_secret(
    local_private_key: x25519.X25519PrivateKey,
    peer_public_bytes: bytes
) -> bytes:
    """Compute raw X25519 shared secret (32 bytes)."""
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    return local_private_key.exchange(peer_public_key)

def derive_traffic_keys(shared_secret: bytes, transcript_hash: bytes) -> tuple[bytes, bytes]:
    """
    Derive directional traffic keys using HKDF-SHA-256.
    
    Formulas:
        PRK = HKDF-Extract(salt = Transcript_Hash, IKM = Shared_Secret)
        K_Alice_to_Bob = HKDF-Expand(PRK, info = "CS6530-A2 Alice->Bob", L = 32)
        K_Bob_to_Alice = HKDF-Expand(PRK, info = "CS6530-A2 Bob->Alice", L = 32)
    """
    # Step 1: HKDF-Extract
    prk = hmac.new(transcript_hash, shared_secret, hashlib.sha256).digest()

    # Step 2: HKDF-Expand (Alice -> Bob)
    hkdf_expand_a2b = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"CS6530-A2 Alice->Bob")
    k_alice_to_bob = hkdf_expand_a2b.derive(prk)

    # Step 3: HKDF-Expand (Bob -> Alice)
    hkdf_expand_b2a = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"CS6530-A2 Bob->Alice")
    k_bob_to_alice = hkdf_expand_b2a.derive(prk)

    return k_alice_to_bob, k_bob_to_alice
# CS6530_Assignment2

## Authenticated Ephemeral Key Establishment

An Ed25519-authenticated X25519 handshake with HKDF-SHA-256 key derivation
and AES-256-GCM record protection, running between two physical machines
over an untrusted IP network.

| | |
|---|---|
| **Sanchit** (CE24B107) | Protocol role: Alice — FR-1 to FR-4, TR-1, TR-2 |
| **Aayush Lal** (CE24B033) | Protocol role: Bob — FR-5 to FR-7, TR-3, TR-4 |

**Cryptographic suite:** X25519 (ephemeral key agreement), Ed25519 (long-term
identity authentication), SHA-256 (transcript hash), HKDF-SHA-256 (traffic-key
derivation), AES-256-GCM (record protection). All primitives come from the
Python `cryptography` library; none were implemented by hand.

---

## 1. Setup

Run these steps on **both** machines.

```bash
git clone https://github.com/Sanchit9587/CS6530_Assignment2.git
cd CS6530_Assignment2
pip install -r requirements.txt
```

If pip reports an externally-managed environment (common with Homebrew Python
on macOS), use a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Identity keys

Each party generates its own long-term Ed25519 key pair:

```bash
python keys/generate_keys.py
```

Then exchange **public** PEM files out of band, so that each machine holds:

- its own `*_lt_private.pem`
- the peer's `*_lt_public.pem`

Private keys are excluded from version control by `.gitignore` and are never
transmitted. Per the assignment scope, peer public keys are assumed authentic;
no PKI is used.

### Network

Both machines must be on the same network. Find the responder's address:

```bash
ipconfig getifaddr en0     # macOS
ip addr                    # Linux
ipconfig                   # Windows (IPv4 Address)
```

Bob binds to `0.0.0.0:5000`, so no router configuration is needed on a shared
LAN. For a quick sanity check before running the protocol, the supplied
connectivity test can be used:

```bash
python Bob_Test.py                 # machine B, start first
python Alice_Test.py <BOB_IP>      # machine A
```

---

## 2. Running the tests

In every test, **start Bob first** — he listens, Alice connects.

### TR-1: Normal authenticated session

Full M1–M4 handshake followed by six protected records (three each way,
counters 0, 1, 2).

```bash
# Laptop B (Bob)
python bob.py 5000 | tee logs/tr1_normal.log

# Laptop A (Alice)
python alice.py <BOB_IP> 5000 | tee logs/tr1_normal_alice.log
```

**Expected:** both signatures verify, both sides print the same transcript
hash, and all six records decrypt correctly. The log shows the raw X25519
shared secret alongside the two derived traffic keys as three distinct values,
confirming the shared secret is not used directly as an AES key.

---

### TR-2: Man-in-the-middle resistance

Mallory intercepts M1 and M2 and substitutes her own ephemeral public keys.

```bash
# Laptop B (Bob)
python bob.py 5000

# Laptop A (Mallory + Alice)
python experiments/test_tr2_mitm.py <BOB_IP> 5000
```

**Expected:** with authentication disabled, Mallory establishes separate
secrets with each party and can read and modify traffic. With full
authentication restored, the substitution changes the transcript, the Ed25519
signature fails to verify at M3/M4, and the session aborts before any traffic
key is derived.

---

### TR-3: Replay resistance

Authentication stays fully enabled. Mallory relays the handshake untouched,
then delivers one application record twice.

```bash
# Laptop B (Bob)
python bob.py 5000 | tee logs/tr3_replay_wire.log

# Laptop A, terminal 1 (Mallory)
python attacks/replay_attacker.py <BOB_IP> 5000 5001

# Laptop A, terminal 2 (Alice — connects to Mallory, not Bob)
python alice.py 127.0.0.1 5001
```

**Expected:** Bob accepts the record at counter 0 and rejects the identical
replay:

```
Bob: <- Validated & Decrypted record (Counter=0): ...
FATAL: Replay/Out-of-order detected. Expected 1, got 0
```

Bob then exits, as FR-6 requires. Alice and Mallory will report a closed
connection — this is the expected consequence of a correct abort, not a
failure.

A standalone version that logs the nonce and AAD of each record explicitly:

```bash
python experiments/test_tr3_replay.py | tee logs/tr3_replay.log
```

---

### TR-4: Forward secrecy

Save-now, compromise-later. This test concerns time rather than distance, so
it runs on a single host.

```bash
python experiments/test_tr4_forward_secrecy.py | tee logs/tr4_forward_secrecy.log
```

**Expected:** after a session runs and its ephemeral secrets are discarded,
compromising Alice's long-term Ed25519 private key does not recover the
recorded traffic. As a controlled comparison, the retained ephemeral X25519
private key recovers the same plaintext immediately — confirming the failure
follows specifically from the deletion of the ephemeral secret.

---

## 3. Repository structure

```
CS6530_Assignment2/
├── transport.py              # supplied TCP helper (unmodified)
├── Alice_Test.py             # supplied connectivity test
├── Bob_Test.py               # supplied connectivity test
│
├── crypto_utils.py           # transcript, Ed25519, X25519, HKDF, AES-GCM helpers
├── secure_channel.py         # FR-5/6/7 record layer as explicit state
├── alice.py                  # Alice: handshake + protected session
├── bob.py                    # Bob: handshake + protected session
│
├── keys/
│   ├── generate_keys.py      # long-term Ed25519 key generation
│   └── *_lt_public.pem       # private keys are gitignored
│
├── attacks/
│   ├── mallory_mitm.py       # TR-2: ephemeral key substitution proxy
│   └── replay_attacker.py    # TR-3: transparent relay that duplicates a record
│
├── experiments/
│   ├── test_tr1_normal.py
│   ├── test_tr2_mitm.py
│   ├── test_tr3_replay.py
│   └── test_tr4_forward_secrecy.py
│
├── logs/                     # captured evidence
└── demo_setup.py             # standalone session helper for the TR-3/TR-4 scripts
```

### A note on the record layer

The repository contains two implementations of the FR-5/FR-6 record logic.
`crypto_utils.py` provides `encrypt_record`/`decrypt_record`, used by the live
`alice.py` and `bob.py` session. `secure_channel.py` provides an equivalent
`SecureChannel` class that encapsulates the directional counters and abort
behaviour as explicit state, used by the standalone TR-3 and TR-4 experiment
scripts. Both construct identical nonces and AAD and are interoperable; the
second exists because the experiment scripts were built before the handshake
was integrated.

---

## 4. Protocol reference

**Canonical transcript (124 bytes):**

```
Protocol_ID(12) || Alice_ID(8) || Bob_ID(8) || Alice_SID(16)
                || Bob_SID(16) || Alice_ePK(32) || Bob_ePK(32)

Transcript_Hash = SHA-256(transcript)      # 32 bytes
```

**Key derivation:**

```
PRK   = HKDF-Extract(salt = Transcript_Hash, IKM = Shared_Secret)
K_A2B = HKDF-Expand(PRK, info = "CS6530-A2 Alice->Bob", L = 32)
K_B2A = HKDF-Expand(PRK, info = "CS6530-A2 Bob->Alice", L = 32)
```

The `cryptography` library exposes no standalone HKDF-Extract, so the extract
step is performed directly from its RFC 5869 definition as
`hmac.new(transcript_hash, shared_secret, hashlib.sha256)`.

**Record protection:**

```
nonce(c) = 0x00000000 || uint64_be(c)                              # 12 bytes
AAD(c)   = Sender_ID || Receiver_ID || Alice_SID || Bob_SID
                     || uint64_be(c)                               # 56 bytes
```

Each direction keeps its own `uint64` counter starting at 0. The receiver
accepts only the expected-next counter and derives nonce and AAD from that
expected value, so a stale record fails GCM verification without needing a
separate check.

---

## 5. Notes

- `transport.py` was used unmodified. It provides framing only — no
  confidentiality, authentication, integrity, or replay protection. Every such
  property is supplied by the protocol itself.
- `Alice_Test.py` originally required a command-line IP argument but then
  ignored it, hardcoding `127.0.0.1`. This was corrected to read `sys.argv[1]`.
- No TLS or other secure channel is used anywhere in the implementation.

---

## AI-use disclosure

AI assistance was used for code generation and for drafting the report.

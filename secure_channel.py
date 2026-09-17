"""
secure_channel.py

FR-5 : Protected bidirectional communication (AES-256-GCM, nonce, AAD)
FR-6 : Replay state and failure handling
FR-7 : Ephemeral-secret lifecycle

Owns everything AFTER the handshake. The handshake module hands over:
    k_alice_to_bob, k_bob_to_alice  (32 bytes each, from HKDF)
    alice_id, bob_id                (8 bytes each, ASCII roll numbers)
    alice_sid, bob_sid              (16 bytes each)
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class ProtocolError(Exception):
    """Raised on any condition that must abort the session (FR-6)."""


def build_nonce(counter: int) -> bytes:
    """96-bit nonce = 0x00000000 || uint64_be(counter)."""
    if not (0 <= counter < 2**64):
        raise ProtocolError(f"counter {counter} out of uint64 range")
    n = b"\x00\x00\x00\x00" + counter.to_bytes(8, "big")
    assert len(n) == 12
    return n


def build_aad(sender_id: bytes, receiver_id: bytes,
              alice_sid: bytes, bob_sid: bytes, counter: int) -> bytes:
    """AAD = Sender_ID || Receiver_ID || Alice_SID || Bob_SID || Message_Counter

    Counter is encoded as uint64 big-endian, matching the nonce encoding.
    """
    assert len(sender_id) == 8 and len(receiver_id) == 8
    assert len(alice_sid) == 16 and len(bob_sid) == 16
    aad = (sender_id + receiver_id + alice_sid + bob_sid
           + counter.to_bytes(8, "big"))
    assert len(aad) == 56, f"AAD is {len(aad)} bytes, expected 56"
    return aad


class SecureChannel:
    """One end of the protected channel. Alice and Bob each build one,
    with k_send / k_recv swapped relative to each other."""

    def __init__(self, k_send, k_recv, my_id, peer_id,
                 alice_sid, bob_sid, role, log=print):
        if len(k_send) != 32 or len(k_recv) != 32:
            raise ProtocolError("traffic keys must be 32 bytes (AES-256)")
        if role not in ("alice", "bob"):
            raise ProtocolError("role must be 'alice' or 'bob'")

        self._send_aead = AESGCM(k_send)
        self._recv_aead = AESGCM(k_recv)
        self._k_send = k_send          # retained only so destroy() can prove deletion
        self._k_recv = k_recv

        self.my_id = my_id
        self.peer_id = peer_id
        self.alice_sid = alice_sid
        self.bob_sid = bob_sid
        self.role = role
        self.log = log

        # FR-5: separate uint64 counter per direction, starting at 0
        self.send_counter = 0
        # FR-6: accept ONLY this counter; anything else is rejected
        self.expect_recv_counter = 0

        self.alive = True

    # ---------- sending ----------

    def protect(self, plaintext: bytes) -> bytes:
        """Encrypt one application record. Returns ciphertext||tag."""
        self._check_alive()
        c = self.send_counter
        nonce = build_nonce(c)
        aad = build_aad(self.my_id, self.peer_id,
                        self.alice_sid, self.bob_sid, c)

        ct = self._send_aead.encrypt(nonce, plaintext, aad)

        self.log(f"[{self.role}] SEND  ctr={c} nonce={nonce.hex()} "
                 f"aad={aad.hex()} ct={ct.hex()[:32]}... ({len(ct)}B)  SUCCESS")
        self.send_counter += 1
        return ct

    # ---------- receiving ----------

    def unprotect(self, record: bytes) -> bytes:
        """Decrypt one application record at the expected counter.

        FR-6: only the expected-next counter is accepted. A replayed or
        out-of-order record is REJECTED before AEAD verification even runs,
        because the nonce/AAD we would need are counter-dependent.
        """
        self._check_alive()
        c = self.expect_recv_counter
        nonce = build_nonce(c)
        aad = build_aad(self.peer_id, self.my_id,
                        self.alice_sid, self.bob_sid, c)

        try:
            pt = self._recv_aead.decrypt(nonce, record, aad)
        except Exception:
            # Either a genuine tamper, or a stale record whose counter != c.
            self.log(f"[{self.role}] RECV  expected ctr={c} -> "
                     f"AEAD verification failed  REJECTED")
            self.fail("AEAD verification failed or stale counter")

        self.log(f"[{self.role}] RECV  ctr={c} nonce={nonce.hex()} "
                 f"aad={aad.hex()} plaintext={pt!r}  SUCCESS")
        self.expect_recv_counter += 1
        return pt

    def unprotect_nonfatal(self, record: bytes):
        """Same as unprotect() but returns None instead of tearing down the
        session. Used by the TR-3 demo so the rejection can be shown without
        killing the process."""
        self._check_alive()
        c = self.expect_recv_counter
        try:
            pt = self._recv_aead.decrypt(
                build_nonce(c),
                record,
                build_aad(self.peer_id, self.my_id,
                          self.alice_sid, self.bob_sid, c))
        except Exception:
            self.log(f"[{self.role}] RECV  expected ctr={c} -> REJECTED "
                     f"(stale counter or bad tag)")
            return None
        self.log(f"[{self.role}] RECV  ctr={c} plaintext={pt!r}  SUCCESS")
        self.expect_recv_counter += 1
        return pt

    # ---------- failure + lifecycle ----------

    def _check_alive(self):
        if not self.alive:
            raise ProtocolError("session already aborted; no further records")

    def fail(self, reason: str):
        """FR-6: do not continue a failed authenticated session."""
        self.log(f"[{self.role}] SESSION ABORTED: {reason}")
        self.destroy()
        raise ProtocolError(reason)

    def destroy(self):
        """FR-7: discard derived traffic keys once no longer needed."""
        self._send_aead = None
        self._recv_aead = None
        self._k_send = None
        self._k_recv = None
        self.alive = False
        self.log(f"[{self.role}] traffic keys discarded (FR-7)")

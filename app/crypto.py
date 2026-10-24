"""Envelope encryption + chunked AES-256-GCM + HMAC-SHA256.

File format (.enc):
  header = b"SDB1" | chunk_size(4) | nonce_prefix(8)
  then repeated: ct_len(4) | ciphertext(+16 byte GCM tag)
Each chunk: nonce = prefix | counter(4); AAD = header | counter | final_flag.
The counter stops reordering; the final flag stops truncation.
"""
import hashlib, hmac, os
from typing import Iterator
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"SDB1"
CHUNK = 4 * 1024 * 1024
TAG = 16


class IntegrityError(Exception):
    pass


def derive(master: bytes, purpose: bytes) -> bytes:
    """Separate keys per purpose (key-wrap, HMAC, DB credentials)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=purpose).derive(master)


def new_data_key() -> bytes:
    return os.urandom(32)


def wrap_key(data_key: bytes, master: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(derive(master, b"key-wrap")).encrypt(nonce, data_key, None)


def unwrap_key(wrapped: bytes, master: bytes) -> bytes:
    try:
        return AESGCM(derive(master, b"key-wrap")).decrypt(wrapped[:12], wrapped[12:], None)
    except Exception as e:
        raise IntegrityError("cannot unwrap data key") from e


def encrypt_text(text: str, master: bytes) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(derive(master, b"db-credentials")).encrypt(nonce, text.encode(), None)
    return (nonce + ct).hex()


def decrypt_text(token: str, master: bytes) -> str:
    raw = bytes.fromhex(token)
    return AESGCM(derive(master, b"db-credentials")).decrypt(raw[:12], raw[12:], None).decode()


def encrypt_file(src: str, dst: str, data_key: bytes) -> None:
    prefix = os.urandom(8)
    header = MAGIC + CHUNK.to_bytes(4, "big") + prefix
    aes = AESGCM(data_key)
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        fo.write(header)
        counter, cur = 0, fi.read(CHUNK)
        while True:
            nxt = fi.read(CHUNK)
            final = not nxt
            ctr = counter.to_bytes(4, "big")
            ct = aes.encrypt(prefix + ctr, cur, header + ctr + (b"\x01" if final else b"\x00"))
            fo.write(len(ct).to_bytes(4, "big") + ct)
            if final:
                break
            cur, counter = nxt, counter + 1


def decrypt_stream(path: str, data_key: bytes) -> Iterator[bytes]:
    """Yields plaintext chunks; raises IntegrityError on any modification."""
    aes = AESGCM(data_key)
    with open(path, "rb") as fi:
        header = fi.read(16)
        if len(header) != 16 or header[:4] != MAGIC:
            raise IntegrityError("bad header")
        prefix = header[8:16]
        counter = 0
        while True:
            raw_len = fi.read(4)
            if len(raw_len) != 4:
                raise IntegrityError("truncated file")
            n = int.from_bytes(raw_len, "big")
            if n < TAG or n > CHUNK + TAG:
                raise IntegrityError("bad chunk length")
            ct = fi.read(n)
            if len(ct) != n:
                raise IntegrityError("truncated chunk")
            pos = fi.tell()
            final = not fi.read(1)
            fi.seek(pos)
            ctr = counter.to_bytes(4, "big")
            try:
                yield aes.decrypt(prefix + ctr, ct, header + ctr + (b"\x01" if final else b"\x00"))
            except Exception as e:
                raise IntegrityError(f"chunk {counter} failed authentication") from e
            if final:
                return
            counter += 1


def decrypt_file(src: str, dst: str, data_key: bytes) -> None:
    with open(dst, "wb") as fo:
        for chunk in decrypt_stream(src, data_key):
            fo.write(chunk)


def hmac_file(path: str, master: bytes) -> str:
    h = hmac.new(derive(master, b"backup-hmac"), digestmod=hashlib.sha256)
    with open(path, "rb") as f:
        while block := f.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def hmac_matches(path: str, expected: str, master: bytes) -> bool:
    return hmac.compare_digest(hmac_file(path, master), expected)

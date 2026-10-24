import os
import struct
import hmac
import hashlib
import base64
import ctypes
from typing import BinaryIO, Generator, Tuple
from app.config import settings

# Load libcrypto-3.dll or standard cryptography if available
_libcrypto = None
try:
    # Check Python's bundled libcrypto-3.dll
    py_dll_path = os.path.join(os.path.dirname(os.path.dirname(ctypes.__file__)), "DLLs", "libcrypto-3.dll")
    if os.path.exists(py_dll_path):
        _libcrypto = ctypes.CDLL(py_dll_path)
    else:
        _libcrypto = ctypes.CDLL("libcrypto-3.dll")
except Exception:
    _libcrypto = None

# Fallback or standard ctypes EVP function bindings
if _libcrypto:
    _libcrypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    _libcrypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    _libcrypto.EVP_aes_256_gcm.restype = ctypes.c_void_p
    _libcrypto.EVP_aes_256_wrap.restype = ctypes.c_void_p
    _libcrypto.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    _libcrypto.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_void_p, ctypes.c_int]
    _libcrypto.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    _libcrypto.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    _libcrypto.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_void_p, ctypes.c_int]
    _libcrypto.EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    _libcrypto.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    _libcrypto.EVP_CIPHER_CTX_set_flags.argtypes = [ctypes.c_void_p, ctypes.c_int]

EVP_CTRL_GCM_SET_IVLEN = 0x9
EVP_CTRL_GCM_GET_TAG = 0x10
EVP_CTRL_GCM_SET_TAG = 0x11
EVP_CIPHER_CTX_FLAG_WRAP_ALLOW = 1

# Magic file header for SecureDB encrypted backups
HEADER_MAGIC = b"SECDB01\x00"  # 8 bytes

class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass

class AuthenticationTagError(CryptoError):
    """Raised when GCM tag verification fails (tampering detected)."""
    pass

class TruncatedBackupError(CryptoError):
    """Raised when backup file is unexpectedly truncated or missing final chunk."""
    pass

class SequenceTamperedError(CryptoError):
    """Raised when chunks are reordered, injected, or skipped."""
    pass


def get_master_key() -> bytes:
    """Retrieve the 32-byte master key from settings."""
    hex_key = settings.MASTER_KEY_HEX.strip()
    try:
        raw = bytes.fromhex(hex_key)
        if len(raw) == 32:
            return raw
    except ValueError:
        pass
    # If not valid 32-byte hex, use SHA-256 of the string
    return hashlib.sha256(hex_key.encode("utf-8")).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract step."""
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-Expand step."""
    hash_len = 32
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def derive_key(master_key: bytes, info: bytes, salt: bytes = b"securedb-salt-v1", length: int = 32) -> bytes:
    """Derive a subkey using RFC 5869 HKDF-SHA256."""
    prk = hkdf_extract(salt, master_key)
    return hkdf_expand(prk, info, length)


def get_key_wrap_key() -> bytes:
    """Derive key for wrapping per-backup DEKs."""
    return derive_key(get_master_key(), b"key-wrap")


def get_backup_hmac_key() -> bytes:
    """Derive key for backup file HMAC-SHA256 integrity."""
    return derive_key(get_master_key(), b"backup-hmac")


def get_db_credentials_key() -> bytes:
    """Derive key for encrypting stored database passwords."""
    return derive_key(get_master_key(), b"db-credentials")


# --- AES-256 Key Wrap (RFC 3394) ---

def wrap_dek(key_wrap_key: bytes, dek: bytes) -> bytes:
    """Wrap a 256-bit (32-byte) DEK using AES Key Wrap (RFC 3394)."""
    if len(dek) % 8 != 0:
        raise ValueError("Data key length must be a multiple of 8 bytes")
    
    if _libcrypto:
        ctx = _libcrypto.EVP_CIPHER_CTX_new()
        try:
            _libcrypto.EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW)
            _libcrypto.EVP_EncryptInit_ex(ctx, _libcrypto.EVP_aes_256_wrap(), None, key_wrap_key, None)
            out_buf = ctypes.create_string_buffer(len(dek) + 16)
            outlen = ctypes.c_int()
            _libcrypto.EVP_EncryptUpdate(ctx, out_buf, ctypes.byref(outlen), dek, len(dek))
            total_len = outlen.value
            tail_ptr = ctypes.cast(ctypes.addressof(out_buf) + total_len, ctypes.c_void_p)
            _libcrypto.EVP_EncryptFinal_ex(ctx, tail_ptr, ctypes.byref(outlen))
            total_len += outlen.value
            return out_buf.raw[:total_len]
        finally:
            _libcrypto.EVP_CIPHER_CTX_free(ctx)
    else:
        # Standard RFC 3394 AES Key Wrap in pure Python if OpenSSL not loaded
        from cryptography.hazmat.primitives.keywrap import aes_key_wrap
        return aes_key_wrap(key_wrap_key, dek)


def unwrap_dek(key_wrap_key: bytes, wrapped_dek: bytes) -> bytes:
    """Unwrap a 256-bit (32-byte) DEK using AES Key Unwrap (RFC 3394)."""
    if _libcrypto:
        ctx = _libcrypto.EVP_CIPHER_CTX_new()
        try:
            _libcrypto.EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW)
            _libcrypto.EVP_DecryptInit_ex(ctx, _libcrypto.EVP_aes_256_wrap(), None, key_wrap_key, None)
            out_buf = ctypes.create_string_buffer(len(wrapped_dek))
            outlen = ctypes.c_int()
            _libcrypto.EVP_DecryptUpdate(ctx, out_buf, ctypes.byref(outlen), wrapped_dek, len(wrapped_dek))
            total_len = outlen.value
            tail_ptr = ctypes.cast(ctypes.addressof(out_buf) + total_len, ctypes.c_void_p)
            ret = _libcrypto.EVP_DecryptFinal_ex(ctx, tail_ptr, ctypes.byref(outlen))
            total_len += outlen.value
            if ret <= 0:
                raise AuthenticationTagError("Unwrapping DEK failed: integrity check failed")
            return out_buf.raw[:total_len]
        finally:
            _libcrypto.EVP_CIPHER_CTX_free(ctx)
    else:
        from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
        return aes_key_unwrap(key_wrap_key, wrapped_dek)


# --- AES-256-GCM Single Chunk / Credential Encrypt & Decrypt ---

def aes_256_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM. Returns (ciphertext, tag_16bytes)."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (AES-256)")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")
    
    if _libcrypto:
        ctx = _libcrypto.EVP_CIPHER_CTX_new()
        try:
            _libcrypto.EVP_EncryptInit_ex(ctx, _libcrypto.EVP_aes_256_gcm(), None, None, None)
            _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(nonce), None)
            _libcrypto.EVP_EncryptInit_ex(ctx, None, None, key, nonce)
            
            outlen = ctypes.c_int()
            if aad:
                _libcrypto.EVP_EncryptUpdate(ctx, None, ctypes.byref(outlen), aad, len(aad))
            
            ciphertext_buf = ctypes.create_string_buffer(len(plaintext) + 16)
            if plaintext:
                _libcrypto.EVP_EncryptUpdate(ctx, ciphertext_buf, ctypes.byref(outlen), plaintext, len(plaintext))
                ct_len = outlen.value
            else:
                ct_len = 0
            
            tail_ptr = ctypes.cast(ctypes.addressof(ciphertext_buf) + ct_len, ctypes.c_void_p)
            _libcrypto.EVP_EncryptFinal_ex(ctx, tail_ptr, ctypes.byref(outlen))
            ct_len += outlen.value
            
            tag_buf = ctypes.create_string_buffer(16)
            _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag_buf)
            
            return ciphertext_buf.raw[:ct_len], tag_buf.raw[:16]
        finally:
            _libcrypto.EVP_CIPHER_CTX_free(ctx)
    else:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        combined = aesgcm.encrypt(nonce, plaintext, aad)
        return combined[:-16], combined[-16:]


def aes_256_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """Decrypt ciphertext with AES-256-GCM. Verifies tag & aad. Raises AuthenticationTagError on mismatch."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (AES-256)")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")
    if len(tag) != 16:
        raise ValueError("Tag must be 16 bytes")
    
    if _libcrypto:
        ctx = _libcrypto.EVP_CIPHER_CTX_new()
        try:
            _libcrypto.EVP_DecryptInit_ex(ctx, _libcrypto.EVP_aes_256_gcm(), None, None, None)
            _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(nonce), None)
            _libcrypto.EVP_DecryptInit_ex(ctx, None, None, key, nonce)
            
            outlen = ctypes.c_int()
            if aad:
                _libcrypto.EVP_DecryptUpdate(ctx, None, ctypes.byref(outlen), aad, len(aad))
            
            plain_buf = ctypes.create_string_buffer(len(ciphertext) + 16)
            if ciphertext:
                _libcrypto.EVP_DecryptUpdate(ctx, plain_buf, ctypes.byref(outlen), ciphertext, len(ciphertext))
                pt_len = outlen.value
            else:
                pt_len = 0
            
            # Set expected tag
            _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)
            
            tail_ptr = ctypes.cast(ctypes.addressof(plain_buf) + pt_len, ctypes.c_void_p)
            ret = _libcrypto.EVP_DecryptFinal_ex(ctx, tail_ptr, ctypes.byref(outlen))
            if ret <= 0:
                raise AuthenticationTagError("AES-256-GCM tag verification failed (ciphertext or AAD tampered)")
            
            pt_len += outlen.value
            return plain_buf.raw[:pt_len]
        finally:
            _libcrypto.EVP_CIPHER_CTX_free(ctx)
    else:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext + tag, aad)
        except InvalidTag:
            raise AuthenticationTagError("AES-256-GCM tag verification failed (ciphertext or AAD tampered)")


# --- Database Credential Encryption ---

def encrypt_credential(plaintext: str) -> str:
    """Encrypt a database password for secure storage using AES-256-GCM."""
    key = get_db_credentials_key()
    nonce = os.urandom(12)
    ct, tag = aes_256_gcm_encrypt(key, nonce, plaintext.encode("utf-8"), aad=b"SECUREDB_CRED_V1")
    packed = nonce + tag + ct
    return base64.b64encode(packed).decode("ascii")


def decrypt_credential(encrypted_b64: str) -> str:
    """Decrypt a database password."""
    key = get_db_credentials_key()
    packed = base64.b64decode(encrypted_b64.encode("ascii"))
    if len(packed) < 28:
        raise ValueError("Invalid encrypted credential format")
    nonce = packed[:12]
    tag = packed[12:28]
    ct = packed[28:]
    plaintext_bytes = aes_256_gcm_decrypt(key, nonce, ct, tag, aad=b"SECUREDB_CRED_V1")
    return plaintext_bytes.decode("utf-8")


# --- Stream Encryption & Decryption Pipeline ---

def encrypt_stream(
    in_stream: BinaryIO,
    out_stream: BinaryIO,
    chunk_size: int = None
) -> Tuple[str, int]:
    """
    Encrypt in_stream into out_stream using Envelope Encryption and 4 MB AES-256-GCM chunks.
    Header contains wrapped DEK.
    Each chunk binds counter and is_final flag into AAD.
    Also computes and returns (HMAC-SHA256 hex of the encrypted output, total_bytes_written).
    """
    if chunk_size is None:
        chunk_size = settings.CHUNK_SIZE
    
    # 1. Generate random 256-bit DEK
    dek = os.urandom(32)
    wrap_key = get_key_wrap_key()
    wrapped_dek = wrap_dek(wrap_key, dek)
    
    # 2. Random 8-byte nonce prefix
    nonce_prefix = os.urandom(8)
    
    # 3. Write Header:
    # MAGIC (8 bytes) + wrapped_dek_len (2B) + wrapped_dek + nonce_prefix (8B) + chunk_size (4B)
    header = (
        HEADER_MAGIC +
        struct.pack(">H", len(wrapped_dek)) +
        wrapped_dek +
        nonce_prefix +
        struct.pack(">I", chunk_size)
    )
    header_hash = hashlib.sha256(header).digest()
    
    # Start HMAC computation over the entire ciphertext stream
    hmac_key = get_backup_hmac_key()
    file_hmac = hmac.new(hmac_key, digestmod=hashlib.sha256)
    
    out_stream.write(header)
    file_hmac.update(header)
    total_bytes = len(header)
    
    # 4. Stream chunks with lookahead to identify final chunk
    counter = 0
    buffer = in_stream.read(chunk_size)
    
    while True:
        next_buffer = in_stream.read(chunk_size)
        is_final = 1 if len(next_buffer) == 0 else 0
        
        # Nonce = 8-byte prefix + 4-byte big-endian counter (total 12 bytes)
        nonce = nonce_prefix + struct.pack(">I", counter)
        
        # AAD binds chunk counter, final flag, and header hash
        aad = b"SECDB_CHUNK:" + struct.pack(">IB", counter, is_final) + header_hash
        
        ciphertext, tag = aes_256_gcm_encrypt(dek, nonce, buffer, aad)
        
        # Chunk framing on disk:
        # counter (4B) + is_final (1B) + ciphertext_len (4B) + ciphertext + tag (16B)
        frame_meta = struct.pack(">IBI", counter, is_final, len(ciphertext))
        chunk_data = frame_meta + ciphertext + tag
        
        out_stream.write(chunk_data)
        file_hmac.update(chunk_data)
        total_bytes += len(chunk_data)
        
        if is_final:
            break
        
        counter += 1
        buffer = next_buffer
    
    return file_hmac.hexdigest(), total_bytes


def decrypt_stream(in_stream: BinaryIO, out_stream: BinaryIO) -> int:
    """
    Decrypt in_stream into out_stream, verifying:
    - Magic header and DEK unwrap
    - AES-256-GCM authentication tag on every chunk
    - Strict sequence counters and AAD binding (detects reordering)
    - Final chunk flag (detects truncation)
    Returns total plaintext bytes written.
    """
    # 1. Read header
    magic = in_stream.read(len(HEADER_MAGIC))
    if magic != HEADER_MAGIC:
        raise CryptoError("Invalid backup file: magic header mismatch")
    
    wrapped_len_bytes = in_stream.read(2)
    if len(wrapped_len_bytes) < 2:
        raise TruncatedBackupError("Header truncated: missing wrapped key length")
    wrapped_len = struct.unpack(">H", wrapped_len_bytes)[0]
    
    wrapped_dek = in_stream.read(wrapped_len)
    if len(wrapped_dek) < wrapped_len:
        raise TruncatedBackupError("Header truncated: missing wrapped DEK")
    
    nonce_prefix = in_stream.read(8)
    if len(nonce_prefix) < 8:
        raise TruncatedBackupError("Header truncated: missing nonce prefix")
    
    chunk_size_bytes = in_stream.read(4)
    if len(chunk_size_bytes) < 4:
        raise TruncatedBackupError("Header truncated: missing chunk size")
    chunk_size = struct.unpack(">I", chunk_size_bytes)[0]
    
    # Reconstruct header bytes to calculate header_hash
    header = (
        magic +
        wrapped_len_bytes +
        wrapped_dek +
        nonce_prefix +
        chunk_size_bytes
    )
    header_hash = hashlib.sha256(header).digest()
    
    # 2. Unwrap DEK
    wrap_key = get_key_wrap_key()
    dek = unwrap_dek(wrap_key, wrapped_dek)
    
    # 3. Read and decrypt chunks
    expected_counter = 0
    total_plaintext_bytes = 0
    seen_final = False
    
    while True:
        meta = in_stream.read(9)  # 4B counter + 1B is_final + 4B ct_len
        if len(meta) == 0:
            # EOF reached
            if not seen_final:
                raise TruncatedBackupError(f"Backup is truncated: EOF reached before final chunk (last counter: {expected_counter-1})")
            break
        if len(meta) < 9:
            raise TruncatedBackupError("Truncated chunk metadata")
        
        counter, is_final, ct_len = struct.unpack(">IBI", meta)
        
        if counter != expected_counter:
            raise SequenceTamperedError(f"Chunk sequence tampered: expected counter {expected_counter}, got {counter}")
        
        ciphertext = in_stream.read(ct_len)
        if len(ciphertext) < ct_len:
            raise TruncatedBackupError(f"Truncated ciphertext in chunk {counter}: expected {ct_len} bytes, got {len(ciphertext)}")
        
        tag = in_stream.read(16)
        if len(tag) < 16:
            raise TruncatedBackupError(f"Truncated authentication tag in chunk {counter}")
        
        # Verify AES-256-GCM authentication tag and AAD
        nonce = nonce_prefix + struct.pack(">I", counter)
        aad = b"SECDB_CHUNK:" + struct.pack(">IB", counter, is_final) + header_hash
        
        plaintext = aes_256_gcm_decrypt(dek, nonce, ciphertext, tag, aad)
        
        out_stream.write(plaintext)
        total_plaintext_bytes += len(plaintext)
        
        if is_final == 1:
            seen_final = True
            # Check if extra trailing bytes exist
            trailing = in_stream.read(1)
            if trailing:
                raise SequenceTamperedError("Extra data detected after final chunk")
            break
        
        expected_counter += 1
    
    return total_plaintext_bytes


# --- HMAC File Integrity ---

def compute_file_hmac(file_path: str) -> str:
    """Compute HMAC-SHA256 hex digest of a file using derived backup_hmac_key."""
    hmac_key = get_backup_hmac_key()
    h = hmac.new(hmac_key, digestmod=hashlib.sha256)
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(64 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def verify_file_hmac(file_path: str, expected_hmac_hex: str) -> bool:
    """Verify HMAC-SHA256 of file against expected value using constant-time comparison."""
    if not os.path.exists(file_path):
        return False
    computed = compute_file_hmac(file_path)
    return hmac.compare_digest(computed.lower(), expected_hmac_hex.lower())

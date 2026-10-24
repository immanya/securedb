import io
import os
import struct
import pytest
from app.core.crypto import (
    encrypt_stream,
    decrypt_stream,
    compute_file_hmac,
    verify_file_hmac,
    wrap_dek,
    unwrap_dek,
    get_key_wrap_key,
    get_backup_hmac_key,
    encrypt_credential,
    decrypt_credential,
    AuthenticationTagError,
    TruncatedBackupError,
    SequenceTamperedError
)

def test_key_wrap_roundtrip():
    """Verify AES Key Wrap (RFC 3394) wraps and unwraps 256-bit DEK."""
    wrap_key = get_key_wrap_key()
    dek = os.urandom(32)
    wrapped = wrap_dek(wrap_key, dek)
    assert len(wrapped) == 40  # 32 bytes data + 8 bytes RFC 3394 integrity
    unwrapped = unwrap_dek(wrap_key, wrapped)
    assert unwrapped == dek

def test_credential_encryption():
    """Verify stored DB passwords encrypt with AES-GCM and decrypt cleanly."""
    pwd = "ComplexP@ssw0rd!_2026"
    encrypted = encrypt_credential(pwd)
    assert encrypted != pwd
    decrypted = decrypt_credential(encrypted)
    assert decrypted == pwd

def test_encrypt_decrypt_empty_file():
    """Roundtrip encryption on empty 0-byte file (handles single final chunk)."""
    in_buf = io.BytesIO(b"")
    out_buf = io.BytesIO()
    hmac_digest, total_bytes = encrypt_stream(in_buf, out_buf)
    
    assert total_bytes > 0  # Contains header + final empty chunk + tag
    out_buf.seek(0)
    
    decrypted_buf = io.BytesIO()
    decrypt_stream(out_buf, decrypted_buf)
    assert decrypted_buf.getvalue() == b""

def test_encrypt_decrypt_small_file():
    """Roundtrip encryption on typical SQL dump snippet."""
    plaintext = b"CREATE TABLE users (id INT, name TEXT);\nINSERT INTO users VALUES (1, 'Admin');"
    in_buf = io.BytesIO(plaintext)
    out_buf = io.BytesIO()
    hmac_digest, total_bytes = encrypt_stream(in_buf, out_buf)
    
    out_buf.seek(0)
    decrypted_buf = io.BytesIO()
    decrypt_stream(out_buf, decrypted_buf)
    assert decrypted_buf.getvalue() == plaintext

def test_encrypt_decrypt_multi_chunk():
    """Roundtrip on file spanning multiple 4MB chunks (tested with custom small chunks)."""
    # 5 chunks of 1KB = 5KB
    test_data = b"SECUREDB-MULTI-CHUNK-TEST-PATTERN-" * 200
    in_buf = io.BytesIO(test_data)
    out_buf = io.BytesIO()
    hmac_digest, total_bytes = encrypt_stream(in_buf, out_buf, chunk_size=1024)
    
    out_buf.seek(0)
    decrypted_buf = io.BytesIO()
    decrypt_stream(out_buf, decrypted_buf)
    assert decrypted_buf.getvalue() == test_data

def test_flipped_byte_detection(tmp_path):
    """Verify that flipping 1 bit is detected by Level 2 HMAC and Level 3 GCM tag."""
    data = b"CRITICAL_FINANCIAL_DATABASE_RECORDS_ACCOUNTS_BALANCES"
    in_buf = io.BytesIO(data)
    out_buf = io.BytesIO()
    hmac_digest, total_bytes = encrypt_stream(in_buf, out_buf)
    
    raw_enc = bytearray(out_buf.getvalue())
    
    # Write legitimate file
    legit_file = tmp_path / "legit.secdb"
    legit_file.write_bytes(raw_enc)
    assert verify_file_hmac(str(legit_file), hmac_digest) is True
    
    # Flip exactly ONE bit in ciphertext
    raw_enc[80] ^= 0x01
    tampered_file = tmp_path / "tampered.secdb"
    tampered_file.write_bytes(raw_enc)
    
    # 1. Level 2 HMAC check must fail
    assert verify_file_hmac(str(tampered_file), hmac_digest) is False
    
    # 2. Level 3 AES-GCM tag verification must fail with AuthenticationTagError
    with pytest.raises(AuthenticationTagError):
        decrypt_stream(io.BytesIO(raw_enc), io.BytesIO())

def test_truncation_detection():
    """Verify that truncated files are detected because final chunk flag was not reached."""
    data = b"Multi-block content for testing truncation detection" * 50
    in_buf = io.BytesIO(data)
    out_buf = io.BytesIO()
    encrypt_stream(in_buf, out_buf, chunk_size=256)
    
    encrypted = out_buf.getvalue()
    # Truncate last 50 bytes (removes final chunk tag or metadata)
    truncated = encrypted[:-50]
    
    with pytest.raises((TruncatedBackupError, AuthenticationTagError)):
        decrypt_stream(io.BytesIO(truncated), io.BytesIO())

def test_chunk_reordering_detection():
    """Verify that swapped chunks are rejected because chunk counter is bound into AAD."""
    # Create multi-chunk ciphertext
    chunk_size = 64
    data = b"A" * 64 + b"B" * 64 + b"C" * 64
    in_buf = io.BytesIO(data)
    out_buf = io.BytesIO()
    encrypt_stream(in_buf, out_buf, chunk_size=chunk_size)
    
    enc_bytes = out_buf.getvalue()
    
    # Read header length
    # MAGIC(8) + wrapped_len(2) + wrapped_key(40) + nonce_prefix(8) + chunk_size(4) = 62 bytes
    header_len = 62
    header = enc_bytes[:header_len]
    chunks_data = enc_bytes[header_len:]
    
    # Each chunk has: meta(9B) + ct(64B) + tag(16B) = 89 bytes
    chunk_len = 9 + 64 + 16
    chunk0 = chunks_data[:chunk_len]
    chunk1 = chunks_data[chunk_len:chunk_len*2]
    rest = chunks_data[chunk_len*2:]
    
    # Swap chunk0 and chunk1
    swapped_stream = io.BytesIO(header + chunk1 + chunk0 + rest)
    
    # Reading chunk 1 first expects counter 0, but counter is 1
    with pytest.raises((SequenceTamperedError, AuthenticationTagError)):
        decrypt_stream(swapped_stream, io.BytesIO())

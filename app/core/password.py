import os
import hmac
import hashlib
import base64
import secrets

# Try importing argon2, fallback gracefully if system policy blocks _ffi
_has_argon2 = False
try:
    import argon2
    _ph = argon2.PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16
    )
    _has_argon2 = True
except Exception:
    _has_argon2 = False


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id (or secure PBKDF2-SHA256 fallback)."""
    if _has_argon2:
        return _ph.hash(password)
    
    # Secure PBKDF2-HMAC-SHA256 fallback (600,000 iterations per OWASP recommendations)
    salt = secrets.token_bytes(16)
    salt_b64 = base64.b64encode(salt).decode("ascii")
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600000)
    hash_b64 = base64.b64encode(derived).decode("ascii")
    return f"$pbkdf2-sha256$i=600000${salt_b64}${hash_b64}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password in constant time."""
    if hashed_password.startswith("$argon2id$") or hashed_password.startswith("$argon2i$"):
        if _has_argon2:
            try:
                return _ph.verify(hashed_password, plain_password)
            except Exception:
                return False
        else:
            # If stored as argon2 but argon2 cannot be loaded on this environment
            return False
            
    if hashed_password.startswith("$pbkdf2-sha256$"):
        try:
            parts = hashed_password.split("$")
            # Format: ["", "pbkdf2-sha256", "i=600000", "<salt_b64>", "<hash_b64>"]
            iter_str = parts[2]
            iterations = int(iter_str.split("=")[1])
            salt = base64.b64decode(parts[3].encode("ascii"))
            expected_hash = base64.b64decode(parts[4].encode("ascii"))
            
            derived = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
            return hmac.compare_digest(derived, expected_hash)
        except Exception:
            return False
            
    return False

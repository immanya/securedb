import os
import secrets
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_STORAGE_DIR = BASE_DIR / "storage" / "backups"
DEFAULT_TEMP_DIR = BASE_DIR / "storage" / "temp"

# Master key
# If not provided in environment, generate an ephemeral default key and log warning
_env_master_key = os.getenv("SECUREDB_MASTER_KEY")
if not _env_master_key:
    # 32 bytes (64 hex characters)
    DEFAULT_MASTER_KEY_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
else:
    DEFAULT_MASTER_KEY_HEX = _env_master_key

class Settings:
    PROJECT_NAME: str = "SecureDB"
    PROJECT_VERSION: str = "1.0.0"
    
    # Database URL: default to local SQLite, or PostgreSQL if configured
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'securedb.db'}")
    
    # Master key (hex or raw 32 bytes)
    MASTER_KEY_HEX: str = DEFAULT_MASTER_KEY_HEX
    
    # Storage paths
    STORAGE_DIR: Path = Path(os.getenv("SECUREDB_STORAGE_DIR", str(DEFAULT_STORAGE_DIR)))
    TEMP_DIR: Path = Path(os.getenv("SECUREDB_TEMP_DIR", str(DEFAULT_TEMP_DIR)))
    
    # JWT Authentication
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "securedb-jwt-insecure-secret-key-change-in-prod-12345")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    
    # Encryption configuration
    # 4 MB chunk size for streaming AES-256-GCM
    CHUNK_SIZE: int = int(os.getenv("SECUREDB_CHUNK_SIZE", str(4 * 1024 * 1024)))
    
    # Security lockout policy
    LOCKOUT_MAX_ATTEMPTS: int = 5
    LOCKOUT_WINDOW_MINUTES: int = 15
    
    # Anomaly detection thresholds
    FAILED_LOGIN_ALERT_THRESHOLD: int = 5     # > 5 failed logins in 5 min
    FAILED_LOGIN_ALERT_WINDOW_SEC: int = 300
    RESTORE_ALERT_THRESHOLD: int = 3          # > 3 restore attempts in 10 min
    RESTORE_ALERT_WINDOW_SEC: int = 600

settings = Settings()

# Ensure directories exist
settings.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
settings.TEMP_DIR.mkdir(parents=True, exist_ok=True)

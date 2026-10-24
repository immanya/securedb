import re
from datetime import datetime
from typing import Optional, List, Dict, Any
from app.compat import BaseModel, Field, field_validator

# --- Auth Schemas ---

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", v):
            raise ValueError("Username can only contain alphanumeric characters, underscores, dashes, and dots")
        return v


class UserLogin(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# --- Target Database Schemas ---

class TargetDBCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=64)
    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(5432, ge=1, le=65535)
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=255)
    database_name: str = Field(..., min_length=1, max_length=64)
    db_type: str = Field("postgresql", pattern="^(postgresql|sqlite)$")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", v):
            raise ValueError("Database display name contains invalid characters")
        return v

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", v):
            raise ValueError("Host contains invalid characters")
        return v

    @field_validator("username")
    @classmethod
    def validate_db_username(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Database user contains invalid characters")
        return v

    @field_validator("database_name")
    @classmethod
    def validate_database_name(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Database name contains invalid characters")
        return v


class TargetDBResponse(BaseModel):
    id: int
    name: str
    host: str
    port: int
    username: str
    database_name: str
    db_type: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class TestConnectionRequest(BaseModel):
    target_db_id: Optional[int] = None
    host: Optional[str] = None
    port: Optional[int] = 5432
    username: Optional[str] = None
    password: Optional[str] = None
    database_name: Optional[str] = None
    db_type: Optional[str] = "postgresql"


class TestConnectionResponse(BaseModel):
    success: bool
    message: str
    details: Optional[Dict[str, Any]] = None


# --- Backup Schemas ---

class BackupCreate(BaseModel):
    target_db_id: int


class BackupResponse(BaseModel):
    id: int
    target_db_id: int
    target_db_name: str
    file_path: str
    file_size_bytes: int
    encrypted_file_hmac: str
    status: str
    integrity_status: str
    last_verified_at: Optional[datetime]
    verification_details: Optional[str]
    created_by_user: str
    created_at: datetime

    class Config:
        from_attributes = True


class VerifyResponse(BaseModel):
    backup_id: int
    status: str  # SAFE, TAMPERED, FAILED
    level1_exists: bool
    level2_hmac_valid: bool
    level3_decrypt_valid: bool
    level4_deep_restore_valid: Optional[bool] = None
    details: Dict[str, Any]


class RestoreRequest(BaseModel):
    target_database_name: str = Field(..., min_length=2, max_length=64)
    confirm_password: str = Field(..., min_length=1)

    @field_validator("target_database_name")
    @classmethod
    def validate_restore_db_name(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Target restore database name must only contain alphanumeric characters and underscores")
        return v


class RestoreResponse(BaseModel):
    success: bool
    restored_database_name: str
    message: str
    table_count: Optional[int] = None
    duration_seconds: float


# --- Schedule Schemas ---

class ScheduleCreate(BaseModel):
    target_db_id: int
    cron_expression: str = Field(..., min_length=5, max_length=64)
    retention_count: int = Field(5, ge=1, le=100)


class ScheduleResponse(BaseModel):
    id: int
    target_db_id: int
    target_db_name: str
    cron_expression: str
    retention_count: int
    is_active: bool
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


# --- Audit & Alert Schemas ---

class AuditLogResponse(BaseModel):
    id: int
    timestamp_iso: str
    username: str
    action: str
    resource: str
    status: str
    details_json: str
    prev_hash: str
    entry_hash: str

    class Config:
        from_attributes = True


class AuditVerifyResponse(BaseModel):
    valid: bool
    broken_at_id: Optional[int]
    total_records: int
    details: str


class SecurityAlertResponse(BaseModel):
    id: int
    alert_type: str
    severity: str
    message: str
    status: str
    details_json: str
    created_at: datetime
    resolved_at: Optional[datetime]
    resolved_by: Optional[str]

    class Config:
        from_attributes = True


# --- Dashboard Schemas ---

class DashboardStats(BaseModel):
    total_backups: int
    safe_backups: int
    tampered_backups: int
    failed_backups: int
    open_alerts: int
    total_databases: int
    active_schedules: int


class DashboardCharts(BaseModel):
    backup_size_history: List[Dict[str, Any]]
    status_distribution: List[Dict[str, Any]]
    login_attempts_7days: List[Dict[str, Any]]

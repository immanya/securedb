"""pg_dump -> AES-256-GCM -> HMAC -> metadata; 4-level verify; safe restore."""
import os, re, subprocess, tempfile
from pathlib import Path
from . import crypto
from .config import STORAGE_DIR, master_key
from .models import Backup, TargetDatabase, now

SAFE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_\-]{0,62}$")
SAFE_HOST = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


def _check(target: TargetDatabase) -> None:
    if not (SAFE_NAME.match(target.name) and SAFE_NAME.match(target.username) and SAFE_HOST.match(target.host)):
        raise ValueError("Invalid database name, user or host")


def _run(cmd: list[str], password: str | None = None) -> str:
    env = os.environ.copy()
    if password is not None:
        env["PGPASSWORD"] = password  # never on the command line
    r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=3600)  # no shell=True
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip()[:500] or "command failed")
    return r.stdout


def _conn(t: TargetDatabase) -> list[str]:
    return ["-h", t.host, "-p", str(t.port), "-U", t.username]


def test_connection(t: TargetDatabase, password: str) -> None:
    _check(t)
    _run(["psql", *_conn(t), "-d", t.name, "-tAc", "SELECT 1"], password)


def create_backup(t: TargetDatabase, user_id: int | None) -> Backup:
    _check(t)
    master = master_key()
    password = crypto.decrypt_text(t.encrypted_password, master)
    ts = now().strftime("%Y%m%d_%H%M%S")
    out_dir = STORAGE_DIR / t.name / now().strftime("%Y-%m-%d")
    out_dir.mkdir(parents=True, exist_ok=True)
    enc_path = out_dir / f"{t.name}_{ts}.dump.enc"
    data_key = crypto.new_data_key()
    with tempfile.TemporaryDirectory() as tmp:  # plaintext dump never reaches secure storage
        plain = os.path.join(tmp, "dump")
        os.chmod(tmp, 0o700)
        _run(["pg_dump", "-Fc", *_conn(t), "-d", t.name, "-f", plain], password)
        crypto.encrypt_file(plain, str(enc_path), data_key)
    return Backup(
        database_id=t.id, file_path=str(enc_path), backup_type="full",
        file_size=enc_path.stat().st_size, hmac=crypto.hmac_file(str(enc_path), master),
        wrapped_key=crypto.wrap_key(data_key, master).hex(), created_by=user_id)


def verify(b: Backup, t: TargetDatabase, deep: bool = False) -> dict:
    """Level 1 file, 2 HMAC, 3 decrypt/auth tag, 4 (optional) real restore into a temp DB."""
    master = master_key()
    res = {"file": False, "integrity": False, "encryption": False, "restore": None}
    if not Path(b.file_path).is_file():
        return {**res, "status": "failed", "reason": "file missing"}
    res["file"] = True
    if not crypto.hmac_matches(b.file_path, b.hmac, master):
        return {**res, "status": "tampered", "reason": "HMAC mismatch"}
    res["integrity"] = True
    try:
        key = crypto.unwrap_key(bytes.fromhex(b.wrapped_key), master)
        for _ in crypto.decrypt_stream(b.file_path, key):
            pass
    except crypto.IntegrityError as e:
        return {**res, "status": "tampered", "reason": str(e)}
    res["encryption"] = True
    if deep:
        tmp_name = f"verify_tmp_{b.id}"
        try:
            restore(b, t, tmp_name)
            n = _run(["psql", *_conn(t), "-d", tmp_name, "-tAc",
                      "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"],
                     crypto.decrypt_text(t.encrypted_password, master)).strip()
            res["restore"] = True
            res["tables_restored"] = int(n)
        except Exception as e:
            res["restore"] = False
            return {**res, "status": "failed", "reason": f"restore test failed: {e}"}
        finally:
            _drop(t, tmp_name)
    return {**res, "status": "safe"}


def _drop(t: TargetDatabase, name: str) -> None:
    try:
        _run(["dropdb", "--if-exists", *_conn(t), name], crypto.decrypt_text(t.encrypted_password, master_key()))
    except Exception:
        pass


def restore(b: Backup, t: TargetDatabase, new_db_name: str) -> None:
    """Restores into a NEW database (never overwrites the original)."""
    _check(t)
    if not SAFE_NAME.match(new_db_name):
        raise ValueError("Invalid target database name")
    master = master_key()
    key = crypto.unwrap_key(bytes.fromhex(b.wrapped_key), master)
    password = crypto.decrypt_text(t.encrypted_password, master)
    if not crypto.hmac_matches(b.file_path, b.hmac, master):
        raise crypto.IntegrityError("HMAC mismatch - refusing to restore")
    with tempfile.TemporaryDirectory() as tmp:
        os.chmod(tmp, 0o700)
        plain = os.path.join(tmp, "dump")
        crypto.decrypt_file(b.file_path, plain, key)
        _run(["createdb", *_conn(t), new_db_name], password)
        try:
            _run(["pg_restore", *_conn(t), "-d", new_db_name, "--no-owner", plain], password)
        except Exception:
            _drop(t, new_db_name)
            raise

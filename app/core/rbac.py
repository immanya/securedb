from typing import Set, Dict

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "admin": {
        "*",  # Admin has full system permissions
        "databases:create",
        "databases:view",
        "databases:delete",
        "databases:test",
        "backups:create",
        "backups:view",
        "backups:verify",
        "backups:restore",
        "backups:delete",
        "schedules:create",
        "schedules:view",
        "schedules:delete",
        "logs:view",
        "logs:verify",
        "alerts:view",
        "alerts:resolve",
        "dashboard:view",
    },
    "manager": {
        "databases:view",
        "databases:test",
        "backups:create",
        "backups:view",
        "backups:verify",
        "backups:restore",
        "schedules:view",
        "logs:view",
        "logs:verify",
        "alerts:view",
        "alerts:resolve",
        "dashboard:view",
    },
    "viewer": {
        "databases:view",
        "backups:view",
        "schedules:view",
        "logs:view",
        "logs:verify",
        "alerts:view",
        "dashboard:view",
    },
}

def has_permission(role: str, required_perm: str) -> bool:
    """Check if the given role has the required permission (deny by default)."""
    perms = ROLE_PERMISSIONS.get(role.lower(), set())
    if "*" in perms:
        return True
    return required_perm in perms

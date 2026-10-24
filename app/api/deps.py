from typing import Optional, Callable
from app.compat import Depends, HTTPException, status, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.core.security import decode_access_token
from app.core.rbac import has_permission
from app.core.audit import append_audit_log
from app.core.alerts import trigger_rbac_denial_alert

security_scheme = HTTPBearer(auto_error=False)

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    Authenticate user by verifying the JWT access token and reading
    the role fresh from the database on every request (not trusted from token claims).
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    payload = decode_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    username: str = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # Read user and their current role directly from the DB
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return user


def require_perm(required_perm: str) -> Callable:
    """
    Dependency factory that enforces granular role permissions.
    Denies by default.
    On denial, writes an entry to the immutable audit log and raises a security alert.
    """
    def _perm_checker(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ) -> User:
        if not has_permission(current_user.role, required_perm):
            # 1. Log denial in audit log
            append_audit_log(
                db=db,
                username=current_user.username,
                action="RBAC_DENIED",
                resource=required_perm,
                status="DENIED",
                details={
                    "user_role": current_user.role,
                    "required_permission": required_perm,
                    "reason": "Insufficient role privileges"
                },
                user_id=current_user.id
            )
            
            # 2. Trigger high severity security alert
            trigger_rbac_denial_alert(
                db=db,
                username=current_user.username,
                resource=required_perm,
                action=f"DENIED_{required_perm}"
            )
            
            # 3. Deny request
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: role '{current_user.role}' lacks permission '{required_perm}'"
            )
            
        return current_user
        
    return _perm_checker

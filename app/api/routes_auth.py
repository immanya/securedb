from datetime import datetime, timezone, timedelta
from app.compat import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.schemas.all_schemas import UserRegister, UserLogin, UserResponse, Token
from app.core.password import hash_password, verify_password
from app.core.security import create_access_token
from app.core.audit import append_audit_log
from app.core.alerts import check_failed_login_anomaly
from app.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])

GENERIC_AUTH_ERROR = "Invalid username or password"

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserRegister, db: Session = Depends(get_db)):
    """
    Register a new user account.
    First user registered in the system automatically receives the 'admin' role;
    subsequent users receive the 'viewer' role.
    """
    existing_user = db.query(User).filter(User.username == user_in.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )
    
    # Check if first user
    user_count = db.query(User).count()
    role = "admin" if user_count == 0 else "viewer"
    
    hashed_pwd = hash_password(user_in.password)
    new_user = User(
        username=user_in.username,
        hashed_password=hashed_pwd,
        role=role,
        failed_login_attempts=0
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    append_audit_log(
        db=db,
        username=new_user.username,
        action="USER_REGISTER",
        resource="auth",
        status="SUCCESS",
        details={"assigned_role": role},
        user_id=new_user.id
    )
    
    return new_user


@router.post("/login", response_model=Token)
def login(login_in: UserLogin, db: Session = Depends(get_db)):
    """
    Authenticate user with Argon2id and issue JWT.
    Enforces account lockout (5 failed attempts within 15 minutes).
    Uses identical error message for nonexistent user and wrong password to prevent user enumeration.
    """
    now = datetime.now(timezone.utc)
    user = db.query(User).filter(User.username == login_in.username).first()
    
    # Check lockout on existing user
    if user and user.locked_until:
        # Normalize timezone
        locked_until_utc = user.locked_until.replace(tzinfo=timezone.utc) if user.locked_until.tzinfo is None else user.locked_until
        if now < locked_until_utc:
            remaining_mins = int((locked_until_utc - now).total_seconds() / 60) + 1
            append_audit_log(
                db=db,
                username=user.username,
                action="LOGIN_BLOCKED_LOCKOUT",
                resource="auth",
                status="BLOCKED",
                details={"remaining_minutes": remaining_mins},
                user_id=user.id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is temporarily locked due to excessive failed attempts. Try again in {remaining_mins} minutes."
            )
        else:
            # Lockout expired, reset counters
            user.locked_until = None
            user.failed_login_attempts = 0
            db.commit()
            
    # Verify credentials
    valid = False
    if user:
        valid = verify_password(login_in.password, user.hashed_password)
        
    if not valid:
        # Log failure
        append_audit_log(
            db=db,
            username=login_in.username,
            action="LOGIN_FAILED",
            resource="auth",
            status="FAILURE",
            details={"attempted_username": login_in.username},
            user_id=user.id if user else None
        )
        
        # Track failures on user if user exists
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.locked_until = now + timedelta(minutes=15)
                db.commit()
            else:
                db.commit()
                
        # Automated anomaly detection trigger (>5 failed logins in 5 min)
        check_failed_login_anomaly(db, login_in.username)
        
        # Always return identical error message to prevent enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=GENERIC_AUTH_ERROR
        )
        
    # Successful login: reset failure counter
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()
    
    append_audit_log(
        db=db,
        username=user.username,
        action="LOGIN_SUCCESS",
        resource="auth",
        status="SUCCESS",
        details={"role": user.role},
        user_id=user.id
    )
    
    token = create_access_token(data={"sub": user.username})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user
    }


@router.post("/logout")
def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Log user logout in the audit log."""
    append_audit_log(
        db=db,
        username=current_user.username,
        action="LOGOUT",
        resource="auth",
        status="SUCCESS",
        user_id=current_user.id
    )
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Return the authenticated user's profile and current DB role."""
    return current_user

import math

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog, User
from ..ratelimit import login_throttle
from ..schemas import UserCreate, audit_out, user_out
from ..security import admin_only, audit, create_access_token, get_current_user, hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login")
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    actor = form.username[:64] or "anonymous"
    wait = login_throttle.retry_after(form.username, ip)
    if wait:
        # Checked before the password, so a locked account cannot be brute-forced even with the right guess.
        audit(db, actor, "login_locked", "user", details={"ip": ip, "retry_after_seconds": wait})
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Try again in {math.ceil(wait / 60)} minute(s).",
            headers={"Retry-After": str(wait)},
        )
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not user.is_active or not verify_password(form.password, user.password_hash):
        login_throttle.record_failure(form.username, ip)
        audit(db, actor, "login_failed", "user", details={"reason": "Invalid username or password", "ip": ip})
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    login_throttle.record_success(form.username, ip)
    audit(db, user.username, "login", "user", user.id, {"ip": ip})
    db.commit()
    return {"access_token": create_access_token(user), "token_type": "bearer", "user": user_out(user)}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return user_out(user)


@router.get("/users")
def list_users(_: User = Depends(admin_only), db: Session = Depends(get_db)):
    return [user_out(u) for u in db.query(User).order_by(User.id).all()]


@router.post("/users", status_code=201)
def create_user(body: UserCreate, admin: User = Depends(admin_only), db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=409, detail="Username already exists")
    user = User(
        username=body.username, full_name=body.full_name, role=body.role, password_hash=hash_password(body.password)
    )
    db.add(user)
    db.flush()
    audit(db, admin.username, "user_created", "user", user.id, {"username": user.username, "role": user.role})
    db.commit()
    return user_out(user)


@router.get("/audit")
def audit_log(limit: int = Query(200, ge=1, le=1000), _: User = Depends(admin_only), db: Session = Depends(get_db)):
    return [audit_out(x) for x in db.query(AuditLog).order_by(AuditLog.id.desc()).limit(limit).all()]

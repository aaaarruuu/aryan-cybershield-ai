from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.limiter import limiter
from app.database.session import get_db
from app.models.entities import Role, User
from app.schemas.common import (LoginIn, ProfileUpdate, RegisterIn, RoleUpdate, TokenOut, UserOut)
from app.security.auth import (audit, create_access_token, get_current_user, hash_password,
                               require_admin, verify_password)

router = APIRouter(prefix="/api/auth", tags=["auth"])
_RATE = get_settings().rate_limit_auth


@router.post("/register", response_model=TokenOut, status_code=201)
@limiter.limit(_RATE)
def register(request: Request, body: RegisterIn, db: Session = Depends(get_db)):
    email = body.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    # The very first account bootstraps the platform as admin; everyone after is an analyst.
    is_first = (db.scalar(select(func.count(User.id))) or 0) == 0
    user = User(email=email, full_name=body.full_name.strip(), password_hash=hash_password(body.password),
                role=Role.admin if is_first else Role.analyst)
    db.add(user)
    db.commit()
    audit(db, "auth.register", user, "user", user.id, {"role": user.role.value}, request)
    return TokenOut(access_token=create_access_token(user), user=user)


@router.post("/login", response_model=TokenOut)
@limiter.limit(_RATE)
def login(request: Request, body: LoginIn, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    if not user or not user.is_active or not verify_password(body.password, user.password_hash):
        audit(db, "auth.login_failed", None, "user", "", {"email": body.email.lower()}, request)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
    audit(db, "auth.login", user, "user", user.id, {}, request)
    return TokenOut(access_token=create_access_token(user), user=user)


@router.post("/logout", status_code=204)
def logout(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Server-side logout: bumping token_version invalidates every token issued earlier."""
    user.token_version += 1
    db.commit()
    audit(db, "auth.logout", user, "user", user.id, {}, request)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@router.patch("/me", response_model=UserOut)
def update_me(body: ProfileUpdate, request: Request, user: User = Depends(get_current_user),
              db: Session = Depends(get_db)):
    if body.full_name:
        user.full_name = body.full_name.strip()
    if body.password:
        user.password_hash = hash_password(body.password)
        user.token_version += 1
    db.commit()
    audit(db, "user.profile_update", user, "user", user.id, {"password_changed": bool(body.password)}, request)
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.scalars(select(User).order_by(User.id)).all()


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(user_id: int, body: RoleUpdate, request: Request, admin: User = Depends(require_admin),
                db: Session = Depends(get_db)):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    if target.id == admin.id and (body.role != Role.admin or not body.is_active):
        raise HTTPException(400, "Admins cannot demote or deactivate themselves")
    target.role, target.is_active = body.role, body.is_active
    target.token_version += 1
    db.commit()
    audit(db, "admin.user_update", admin, "user", target.id,
          {"role": body.role.value, "is_active": body.is_active}, request)
    return target

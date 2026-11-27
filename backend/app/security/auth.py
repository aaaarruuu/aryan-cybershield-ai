"""Password hashing, JWT issue/verify, RBAC dependencies, audit helper."""
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.database.session import get_db
from app.models.entities import AuditLog, Role, User

bearer = HTTPBearer(auto_error=False)
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode()[:72], hashed.encode())
    except ValueError:
        return False


def create_access_token(user: User) -> str:
    s = get_settings()
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user.id), "role": user.role.value, "tv": user.token_version,
               "iat": now, "exp": now + timedelta(minutes=s.access_token_expire_minutes)}
    return jwt.encode(payload, s.secret_key, algorithm=ALGORITHM)


def get_current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer),
                     db: Session = Depends(get_db)) -> User:
    err = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired credentials",
                        headers={"WWW-Authenticate": "Bearer"})
    if creds is None:
        raise err
    try:
        payload = jwt.decode(creds.credentials, get_settings().secret_key, algorithms=[ALGORITHM])
        user = db.get(User, int(payload["sub"]))
    except (jwt.PyJWTError, KeyError, ValueError):
        raise err
    if user is None or not user.is_active or payload.get("tv") != user.token_version:
        raise err
    return user


def require_roles(*roles: Role):
    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user
    return checker


require_admin = require_roles(Role.admin)
require_analyst = require_roles(Role.admin, Role.analyst)


def audit(db: Session, action: str, user: User | None = None, entity: str = "", entity_id: str | int = "",
          detail: dict | None = None, request: Request | None = None) -> None:
    """Write an audit record. Callers must never pass secrets in `detail`."""
    db.add(AuditLog(actor_id=user.id if user else None, actor_email=user.email if user else None,
                    action=action, entity=entity, entity_id=str(entity_id), detail=detail or {},
                    ip=request.client.host if request and request.client else None))
    db.commit()

import time
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User
from ..security.jwt_utils import create_access_token, decode_access_token
from ..security.nonce_store import create_nonce, consume_nonce
from ..security.password_utils import verify_password
from ..security.signatures import canonical_payload
from .audit_service import log_event
from .cfl_service import CFLService


bearer_scheme = HTTPBearer()


def create_challenge(db: Session, uid: str, purpose: str = "login") -> dict:
    nonce = create_nonce(db, uid, purpose)
    timestamp = int(time.time())
    payload = {"uid": uid, "nonce": nonce.nonce, "timestamp": timestamp, "purpose": purpose}
    return {**payload, "message": canonical_payload(payload).decode()}


def login_with_password(db: Session, username: str, password: str) -> dict:
    user = db.query(User).filter(User.username == username).first()
    if not user or user.status != "active" or not verify_password(password, user.password_hash):
        log_event(db, "LOGIN_FAILED", action="password_login", result="failed", detail={"username": username}, risk_level="medium")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    log_event(db, "LOGIN_SUCCESS", user=user, action="password_login", result="success")
    return {"access_token": create_access_token(user.username, user.role), "token_type": "bearer", "role": user.role}


def login_with_cfl(db: Session, uid: str, signature: str, nonce: str, timestamp: int) -> dict:
    user = db.query(User).filter(User.username == uid).first()
    if not user or user.status != "active":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid user")
    if abs(int(time.time()) - timestamp) > 300:
        log_event(db, "CFL_VERIFY_FAILED", user=user, action="cfl_login", result="failed", risk_level="medium", detail={"reason": "timestamp_expired"})
        raise HTTPException(status_code=400, detail="timestamp expired")
    if not consume_nonce(db, uid, nonce, "login"):
        log_event(db, "CFL_VERIFY_FAILED", user=user, action="cfl_login", result="failed", risk_level="high", detail={"reason": "nonce_replay"})
        raise HTTPException(status_code=400, detail="nonce invalid or replayed")
    payload = {"uid": uid, "nonce": nonce, "timestamp": timestamp, "purpose": "login"}
    public_key = None
    if user.cfl_public_key_x and user.cfl_public_key_y:
        public_key = {"x": user.cfl_public_key_x, "y": user.cfl_public_key_y}
    if not CFLService().verify(uid, canonical_payload(payload), signature, public_key=public_key):
        log_event(db, "CFL_VERIFY_FAILED", user=user, action="cfl_login", result="failed", risk_level="high")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="signature invalid")
    log_event(db, "CFL_VERIFY_SUCCESS", user=user, action="cfl_login", result="success")
    return {"access_token": create_access_token(user.username, user.role), "token_type": "bearer", "role": user.role}


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    payload = decode_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if not user or user.status != "active":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="user unavailable")
    return user


def require_action(user: User, action: str) -> None:
    from .policy_service import check_permission

    result = check_permission(user, action, "api", {})
    if not result["allow"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=result["reason"])

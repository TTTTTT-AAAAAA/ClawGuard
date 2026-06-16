from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..models import User
from ..database import get_db
from ..schemas import CFLLoginRequest, ChallengeRequest, ChallengeResponse, LoginRequest, TokenResponse
from ..services.auth_service import create_challenge, get_current_user, login_with_cfl, login_with_password
from ..services.cfl_real_service import CFLRealError
from ..services.cfl_service import CFLService


router = APIRouter()


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    return login_with_password(db, payload.username, payload.password)


@router.post("/challenge", response_model=ChallengeResponse)
def challenge(payload: ChallengeRequest, db: Session = Depends(get_db)):
    return create_challenge(db, payload.uid, payload.purpose)


@router.post("/cfl-login", response_model=TokenResponse)
def cfl_login(payload: CFLLoginRequest, db: Session = Depends(get_db)):
    return login_with_cfl(db, payload.uid, payload.signature, payload.nonce, payload.timestamp)


@router.get("/cfl/status")
def cfl_status():
    return CFLService().status()


@router.get("/cfl/public-key/{uid}")
def cfl_public_key(uid: str, user: User = Depends(get_current_user)):
    if user.role != "admin" and user.username != uid:
        raise HTTPException(status_code=403, detail="permission denied")
    try:
        return CFLService().export_public_key(uid)
    except CFLRealError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/cfl/diagnostics")
def cfl_diagnostics(user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="permission denied")
    try:
        return CFLService().diagnostics()
    except CFLRealError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

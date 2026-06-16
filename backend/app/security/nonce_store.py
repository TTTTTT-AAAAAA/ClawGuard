from datetime import datetime, timedelta
import secrets
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import Nonce


def create_nonce(db: Session, uid: str, purpose: str) -> Nonce:
    settings = get_settings()
    nonce = Nonce(
        uid=uid,
        purpose=purpose,
        nonce=secrets.token_hex(16),
        expires_at=datetime.utcnow() + timedelta(seconds=settings.nonce_ttl_seconds),
    )
    db.add(nonce)
    db.commit()
    db.refresh(nonce)
    return nonce


def consume_nonce(db: Session, uid: str, nonce: str, purpose: str) -> bool:
    record = (
        db.query(Nonce)
        .filter(Nonce.uid == uid, Nonce.nonce == nonce, Nonce.purpose == purpose)
        .first()
    )
    if not record or record.used or record.expires_at < datetime.utcnow():
        return False
    record.used = True
    db.commit()
    return True


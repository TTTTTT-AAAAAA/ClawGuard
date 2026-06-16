from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User
from ..schemas import AuditItem
from ..services.auth_service import get_current_user, require_action
from ..services.audit_service import query_events


router = APIRouter()


@router.get("", response_model=dict)
def list_audit(
    event_type: str | None = None,
    uid: str | None = None,
    job_id: str | None = None,
    risk_level: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_action(user, "view_audit")
    items = query_events(db, {"event_type": event_type, "uid": uid, "job_id": job_id, "risk_level": risk_level})
    return {"items": [AuditItem.model_validate(item, from_attributes=True).model_dump() for item in items]}


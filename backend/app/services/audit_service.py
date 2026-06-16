from sqlalchemy.orm import Session

from ..models import AuditLog
from ..security.sanitizer import sanitized_json, sanitize_obj


def log_event(
    db: Session,
    event_type: str,
    user=None,
    action: str | None = None,
    result: str = "success",
    detail: dict | None = None,
    resource: str | None = None,
    risk_level: str = "low",
    ip: str | None = None,
    job_id: str | None = None,
    message: str = "",
) -> AuditLog:
    uid = getattr(user, "username", None) if user else None
    sanitized_detail = sanitize_obj(detail or {})
    record = AuditLog(
        uid=uid,
        event_type=event_type,
        action=action,
        resource=resource,
        result=result,
        risk_level=risk_level,
        ip=ip,
        job_id=job_id,
        message=message,
        detail_json=sanitized_json(sanitized_detail),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def query_events(db: Session, filters: dict) -> list[AuditLog]:
    query = db.query(AuditLog)
    for field in ("event_type", "uid", "job_id", "risk_level"):
        if filters.get(field):
            query = query.filter(getattr(AuditLog, field) == filters[field])
    return query.order_by(AuditLog.timestamp.desc()).limit(200).all()


def sanitize_detail(detail: dict) -> dict:
    return sanitize_obj(detail)


from __future__ import annotations

from datetime import datetime
import json
import secrets

from fastapi import HTTPException
from sqlalchemy.orm import Session

from ..models import BEIJING_TZ, ReviewRequest, User, beijing_now
from .audit_service import log_event
from .command_filter import validate_action
from .input_filter import scan_text
from .task_service import create_task


def _new_review_id() -> str:
    return f"review_{datetime.now(BEIJING_TZ).strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(3)}"


def _loads_json(value: str, default):
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _as_beijing(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.astimezone(BEIJING_TZ).replace(tzinfo=None)
    return value


def _analyze(action: str, params: dict, input_text: str | None, source: str = "openclaw") -> dict:
    command_check = validate_action(action, params)
    filter_result = scan_text(input_text or json.dumps(params, ensure_ascii=False))

    reasons = []
    if not command_check["allow"]:
        reasons.append(f"命令过滤未通过：{command_check['reason']}")
    if filter_result["decision"] == "DENY":
        reasons.append("输入过滤发现高风险内容，建议拒绝或修改后再提交")
    elif filter_result["decision"] == "MASK":
        reasons.append("输入包含敏感字段，建议确认脱敏后再放行")

    if not command_check["allow"] or filter_result["decision"] == "DENY":
        recommendation = "reject"
        risk_level = "high"
    elif filter_result["decision"] == "MASK":
        recommendation = "modify"
        risk_level = "medium"
    else:
        recommendation = "approve"
        risk_level = "low"

    return {
        "source": source,
        "risk_level": risk_level,
        "recommendation": recommendation,
        "reasons": reasons or ["未发现阻断项，可审核通过"],
        "command_check": command_check,
        "filter_result": filter_result,
    }


def _to_response(review: ReviewRequest) -> dict:
    return {
        "review_id": review.review_id,
        "uid": review.uid,
        "action": review.action,
        "params": _loads_json(review.params_json, {}),
        "input_text": review.input_text,
        "status": review.status,
        "recommendation": review.recommendation,
        "filter_decision": review.filter_decision,
        "command_allow": review.command_allow,
        "analysis": _loads_json(review.analysis_json, {}),
        "job_id": review.job_id,
        "created_at": _as_beijing(review.created_at),
        "updated_at": _as_beijing(review.updated_at),
        "reviewed_at": _as_beijing(review.reviewed_at),
    }


def capture_review(db: Session, user: User, action: str, params: dict, input_text: str | None, source: str = "openclaw") -> dict:
    analysis = _analyze(action, params, input_text, source)
    is_low_risk = analysis["risk_level"] == "low" and analysis["recommendation"] == "approve"
    review = ReviewRequest(
        review_id=_new_review_id(),
        uid=user.username,
        action=action,
        params_json=json.dumps(params, ensure_ascii=False),
        input_text=input_text,
        status="PENDING",
        recommendation=analysis["recommendation"],
        filter_decision=analysis["filter_result"]["decision"],
        command_allow=bool(analysis["command_check"]["allow"]),
        analysis_json=json.dumps(analysis, ensure_ascii=False),
    )
    db.add(review)
    db.commit()
    db.refresh(review)

    job = None
    if is_low_risk:
        job = create_task(db, user, action, params, input_text)
        review.status = "APPROVED"
        review.job_id = job.job_id
        review.reviewer_uid = "system"
        review.review_note = "low risk auto approved"
        review.reviewed_at = beijing_now()
        review.updated_at = review.reviewed_at
        db.commit()
        db.refresh(review)

    log_event(
        db,
        "OPENCLAW_AUTO_APPROVED" if is_low_risk else "OPENCLAW_CAPTURED_BLOCKED",
        user=user,
        action=action,
        result="approved" if is_low_risk else "pending",
        risk_level=analysis["risk_level"],
        job_id=job.job_id if job else None,
        detail={"review_id": review.review_id, "analysis": analysis, "auto_approved": is_low_risk},
    )
    return _to_response(review)


def list_reviews(
    db: Session,
    user: User,
    status: str | None = "PENDING",
    filter_decision: str | None = None,
    risk_level: str | None = None,
) -> list[dict]:
    query = db.query(ReviewRequest)
    if user.role not in {"admin", "auditor"}:
        query = query.filter(ReviewRequest.uid == user.username)
    if status and status.upper() not in {"ALL", "*"}:
        query = query.filter(ReviewRequest.status == status)
    if filter_decision:
        query = query.filter(ReviewRequest.filter_decision == filter_decision)
    if risk_level:
        # risk_level is stored inside analysis_json; use LIKE for simplicity
        query = query.filter(ReviewRequest.analysis_json.like(f'%"risk_level": "{risk_level}"%'))
    return [_to_response(item) for item in query.order_by(ReviewRequest.created_at.desc()).limit(200).all()]


def get_review(db: Session, user: User, review_id: str) -> ReviewRequest:
    review = db.query(ReviewRequest).filter(ReviewRequest.review_id == review_id).first()
    if not review or (review.uid != user.username and user.role not in {"admin", "auditor"}):
        raise HTTPException(status_code=404, detail="review not found")
    return review


def update_review(
    db: Session,
    user: User,
    review_id: str,
    action: str | None = None,
    params: dict | None = None,
    input_text: str | None = None,
    note: str | None = None,
) -> dict:
    review = get_review(db, user, review_id)
    if review.status != "PENDING":
        raise HTTPException(status_code=400, detail="only pending reviews can be modified")
    if action is not None:
        review.action = action
    if params is not None:
        review.params_json = json.dumps(params, ensure_ascii=False)
    if input_text is not None:
        review.input_text = input_text
    params_obj = _loads_json(review.params_json, {})
    analysis = _analyze(review.action, params_obj, review.input_text, "review_update")
    review.recommendation = analysis["recommendation"]
    review.filter_decision = analysis["filter_result"]["decision"]
    review.command_allow = bool(analysis["command_check"]["allow"])
    review.analysis_json = json.dumps(analysis, ensure_ascii=False)
    review.reviewer_uid = user.username
    review.review_note = note
    review.updated_at = beijing_now()
    db.commit()
    db.refresh(review)
    log_event(
        db,
        "OPENCLAW_REVIEW_MODIFIED",
        user=user,
        action=review.action,
        result="pending",
        risk_level=analysis["risk_level"],
        detail={"review_id": review.review_id, "note": note, "analysis": analysis},
    )
    return _to_response(review)


def resubmit_review(
    db: Session,
    user: User,
    review_id: str,
    action: str | None = None,
    params: dict | None = None,
    input_text: str | None = None,
    note: str | None = None,
) -> dict:
    review = get_review(db, user, review_id)
    if review.status != "PENDING":
        raise HTTPException(status_code=400, detail="only pending reviews can be resubmitted")

    next_action = action or review.action
    next_params = params if params is not None else _loads_json(review.params_json, {})
    next_input = input_text if input_text is not None else review.input_text

    owner = db.query(User).filter(User.username == review.uid).first() or user
    review.status = "RESUBMITTED"
    review.reviewer_uid = user.username
    review.review_note = note or "modified and resubmitted to OpenClaw capture"
    review.reviewed_at = beijing_now()
    review.updated_at = review.reviewed_at
    db.commit()
    db.refresh(review)

    new_review = capture_review(db, owner, next_action, next_params, next_input, "review_resubmit")
    log_event(
        db,
        "OPENCLAW_REVIEW_RESUBMITTED",
        user=user,
        action=next_action,
        result="resubmitted",
        risk_level=new_review.get("analysis", {}).get("risk_level", "low"),
        job_id=new_review.get("job_id"),
        detail={
            "original_review_id": review.review_id,
            "new_review_id": new_review["review_id"],
            "note": note,
        },
    )
    return new_review


def approve_review(
    db: Session,
    user: User,
    review_id: str,
    note: str | None = None,
    action: str | None = None,
    params: dict | None = None,
    input_text: str | None = None,
) -> dict:
    review = get_review(db, user, review_id)
    if review.status != "PENDING":
        raise HTTPException(status_code=400, detail="review is not pending")
    if action is not None or params is not None or input_text is not None:
        update_review(db, user, review_id, action=action, params=params, input_text=input_text, note=note)
        review = get_review(db, user, review_id)

    executor = db.query(User).filter(User.username == review.uid).first() or user
    params_obj = _loads_json(review.params_json, {})
    task = create_task(db, executor, review.action, params_obj, review.input_text)
    review.status = "APPROVED"
    review.reviewer_uid = user.username
    review.review_note = note
    review.job_id = task.job_id
    review.reviewed_at = beijing_now()
    review.updated_at = review.reviewed_at
    db.commit()
    db.refresh(review)
    log_event(
        db,
        "OPENCLAW_REVIEW_APPROVED",
        user=user,
        action=review.action,
        result="approved",
        job_id=task.job_id,
        detail={"review_id": review.review_id, "note": note},
    )
    return _to_response(review)


def reject_review(db: Session, user: User, review_id: str, note: str | None = None) -> dict:
    review = get_review(db, user, review_id)
    if review.status != "PENDING":
        raise HTTPException(status_code=400, detail="review is not pending")
    review.status = "REJECTED"
    review.reviewer_uid = user.username
    review.review_note = note
    review.reviewed_at = beijing_now()
    review.updated_at = review.reviewed_at
    db.commit()
    db.refresh(review)
    log_event(
        db,
        "OPENCLAW_REVIEW_REJECTED",
        user=user,
        action=review.action,
        result="rejected",
        risk_level=_loads_json(review.analysis_json, {}).get("risk_level", "medium"),
        detail={"review_id": review.review_id, "note": note},
    )
    return _to_response(review)

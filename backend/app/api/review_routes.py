from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User
from ..schemas import ReviewCaptureRequest, ReviewDecisionRequest, ReviewResponse, ReviewUpdateRequest
from ..services.auth_service import get_current_user
from ..services.review_service import approve_review, capture_review, list_reviews, reject_review, resubmit_review, update_review


router = APIRouter()


@router.post("/capture", response_model=ReviewResponse)
def capture_openclaw_task(
    payload: ReviewCaptureRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return capture_review(db, user, payload.action, payload.params, payload.input_text, payload.source)


@router.get("", response_model=dict)
def get_review_queue(
    status: str | None = "PENDING",
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return {"items": list_reviews(db, user, status)}


@router.patch("/{review_id}", response_model=ReviewResponse)
def modify_review(
    review_id: str,
    payload: ReviewUpdateRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return update_review(db, user, review_id, payload.action, payload.params, payload.input_text, payload.note)


@router.post("/{review_id}/resubmit", response_model=ReviewResponse)
def resubmit_openclaw_task(
    review_id: str,
    payload: ReviewUpdateRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return resubmit_review(db, user, review_id, payload.action, payload.params, payload.input_text, payload.note)


@router.post("/{review_id}/approve", response_model=ReviewResponse)
def approve_openclaw_task(
    review_id: str,
    payload: ReviewDecisionRequest | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    payload = payload or ReviewDecisionRequest()
    return approve_review(db, user, review_id, payload.note, payload.action, payload.params, payload.input_text)


@router.post("/{review_id}/reject", response_model=ReviewResponse)
def reject_openclaw_task(
    review_id: str,
    payload: ReviewDecisionRequest | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    payload = payload or ReviewDecisionRequest()
    return reject_review(db, user, review_id, payload.note)

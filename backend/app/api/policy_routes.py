from fastapi import APIRouter, Depends

from ..models import User
from ..services.auth_service import get_current_user, require_action
from ..services.policy_service import load_policy


router = APIRouter()


@router.get("")
def read_policy(user: User = Depends(get_current_user)):
    require_action(user, "manage_policy" if user.role == "admin" else "view_audit")
    return load_policy()


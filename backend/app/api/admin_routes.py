from fastapi import APIRouter, Depends

from ..models import User
from ..services.auth_service import get_current_user, require_action


router = APIRouter()


@router.get("/summary")
def admin_summary(user: User = Depends(get_current_user)):
    require_action(user, "manage_policy")
    return {
        "service": "ClawGuard Web",
        "security_chain": ["auth", "cfl", "input_filter", "command_filter", "pbac", "docker", "audit"],
    }


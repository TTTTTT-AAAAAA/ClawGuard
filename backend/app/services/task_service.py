from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import secrets
from fastapi import HTTPException
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import Task, User, beijing_now
from ..security.sanitizer import sanitize_text
from .audit_service import log_event
from .command_filter import build_safe_command, validate_action
from .docker_runner import get_container_logs, run_job
from .input_filter import scan_file, scan_text
from .policy_service import check_permission


BEIJING_TZ = timezone(timedelta(hours=8))


def _new_job_id() -> str:
    return f"job_{datetime.now(BEIJING_TZ).strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(3)}"


def create_task(db: Session, user: User, action: str, params: dict, input_text: str | None = None) -> Task:
    command_check = validate_action(action, params)
    if not command_check["allow"]:
        log_event(db, "COMMAND_FILTER_DENY", user=user, action=action, result="denied", risk_level="high", detail=command_check)
        raise HTTPException(status_code=400, detail=command_check["reason"])

    filter_result = scan_text(input_text or json.dumps(params, ensure_ascii=False))
    if filter_result["decision"] == "DENY":
        log_event(db, "INPUT_FILTER_DENY", user=user, action=action, result="denied", risk_level="high", detail=filter_result)
        raise HTTPException(status_code=400, detail="input denied by filter")

    policy = check_permission(user, action, "job", {"filter": filter_result["decision"]})
    if not policy["allow"]:
        log_event(db, "POLICY_DENY", user=user, action=action, result="denied", risk_level="medium", detail=policy)
        raise HTTPException(status_code=403, detail=policy["reason"])
    log_event(db, "POLICY_ALLOW", user=user, action=action, result="success", detail=policy)

    job_id = _new_job_id()
    job_dir = Path(get_settings().jobs_dir) / job_id
    input_dir = job_dir / "input"
    output_dir = job_dir / "output"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    (input_dir / "request.json").write_text(json.dumps({"params": params, "input_text": input_text}, ensure_ascii=False, indent=2), encoding="utf-8")

    if scan_file(str(input_dir / "request.json"))["decision"] == "DENY":
        raise HTTPException(status_code=400, detail="stored input denied by filter")

    task = Task(job_id=job_id, uid=user.username, action=action, status="RUNNING", input_path=str(input_dir), output_path=str(output_dir), started_at=beijing_now())
    db.add(task)
    db.commit()
    db.refresh(task)
    log_event(db, "TASK_CREATED", user=user, action=action, result="success", job_id=job_id, detail={"params": params})

    command = build_safe_command(action, params)
    result = run_job(job_id, action, command, policy["docker"])
    task.status = result["status"]
    task.exit_code = result["exit_code"]
    task.container_id = result.get("container_id")
    task.finished_at = beijing_now()
    task.error_message = result.get("warning")
    db.commit()
    log_type = "TASK_SUCCESS" if task.status == "SUCCESS" else "TASK_FAILED"
    log_event(db, log_type, user=user, action=action, result=task.status.lower(), job_id=job_id, detail=result)
    return task


def read_task_logs(job_id: str) -> str:
    return sanitize_text(get_container_logs(job_id))


def read_task_result(job_id: str) -> dict:
    path = Path(get_settings().jobs_dir) / job_id / "output" / "result.json"
    if not path.exists():
        return {"summary": "result file not found"}
    return json.loads(path.read_text(encoding="utf-8"))

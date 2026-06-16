from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Task, User
from ..schemas import TaskCreateRequest, TaskResponse, TaskStatusResponse
from ..services.auth_service import get_current_user
from ..services.task_service import create_task, read_task_logs, read_task_result


router = APIRouter()


@router.post("", response_model=TaskResponse)
def submit_task(payload: TaskCreateRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = create_task(db, user, payload.action, payload.params, payload.input_text)
    return {"job_id": task.job_id, "status": task.status, "message": "task submitted"}


@router.get("/{job_id}", response_model=TaskStatusResponse)
def get_task(job_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.job_id == job_id).first()
    if not task or (task.uid != user.username and user.role not in {"admin", "auditor"}):
        raise HTTPException(status_code=404, detail="task not found")
    return task


@router.get("/{job_id}/logs")
def get_task_logs(job_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.job_id == job_id).first()
    if not task or (task.uid != user.username and user.role not in {"admin", "auditor"}):
        raise HTTPException(status_code=404, detail="task not found")
    return {"job_id": job_id, "logs": read_task_logs(job_id)}


@router.get("/{job_id}/result")
def get_result(job_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.job_id == job_id).first()
    if not task or (task.uid != user.username and user.role not in {"admin", "auditor"}):
        raise HTTPException(status_code=404, detail="task not found")
    return {"job_id": job_id, "result": read_task_result(job_id)}


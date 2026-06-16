import re


ALLOWED_ACTIONS = {
    "run_openclaw": {
        "cmd": ["python", "/workspace/openclaw_stub.py", "run"],
        "need_signature": True,
        "need_network": False,
    },
    "analyze_file": {
        "cmd": ["python", "/workspace/openclaw_stub.py", "analyze"],
        "need_signature": False,
        "need_network": False,
    },
    "export_result": {
        "cmd": ["python", "/workspace/openclaw_stub.py", "export"],
        "need_signature": False,
        "need_network": False,
    },
}
DANGEROUS_TOKENS = re.compile(
    r"(?:\brm\b|\bsudo\b|\bchmod\b|\bchown\b|\bcurl\b|\bwget\b|\bnc\b|\bssh\b|\bscp\b|"
    r"\bdocker\b|\bbash\b|\bsh\b|\bpowershell\b|\bcmd\.exe\b|"
    r"\bcopy\b|\breg\b|\bnet\b|\bsc\b|\bmove\b|\bdel\b|\battrib\b|;|&&|\|\||\||>|<|\$\(|`)",
    re.I,
)


def validate_action(action: str, params: dict) -> dict:
    if action not in ALLOWED_ACTIONS:
        return {"allow": False, "reason": "unknown_action"}
    serialized = " ".join(str(v) for v in params.values())
    if DANGEROUS_TOKENS.search(serialized):
        return {"allow": False, "reason": "dangerous_parameter"}
    return {"allow": True, "reason": "action_allowed", "spec": ALLOWED_ACTIONS[action]}


def build_safe_command(action: str, params: dict) -> list[str]:
    validation = validate_action(action, params)
    if not validation["allow"]:
        raise ValueError(validation["reason"])
    command = list(ALLOWED_ACTIONS[action]["cmd"])
    mode = params.get("mode")
    if mode in {"safe", "strict", "report"}:
        command.extend(["--mode", mode])
    input_name = params.get("input_name")
    if input_name:
        command.extend(["--input", str(input_name)])
    return command


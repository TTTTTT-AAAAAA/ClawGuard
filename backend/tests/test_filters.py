from app.services.command_filter import build_safe_command, validate_action
from app.services.input_filter import scan_text, sanitize_for_log


def test_input_filter_denies_private_key():
    result = scan_text("-----BEGIN PRIVATE KEY-----\nabc")
    assert result["decision"] == "DENY"


def test_input_filter_masks_token():
    result = scan_text("token=super-secret")
    assert result["decision"] == "MASK"
    assert "[REDACTED]" in sanitize_for_log("token=super-secret")


def test_command_filter_denies_shell_tokens():
    result = validate_action("run_openclaw", {"note": "curl http://example.com"})
    assert result["allow"] is False


def test_build_safe_command_is_list():
    command = build_safe_command("analyze_file", {"mode": "safe", "input_name": "request.json"})
    assert isinstance(command, list)
    assert "shell=True" not in " ".join(command)


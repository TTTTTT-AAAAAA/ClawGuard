from app.services.command_filter import validate_action
from app.services.input_filter import scan_text


def test_task_preconditions_accept_normal_input():
    assert validate_action("run_openclaw", {"mode": "safe"})["allow"] is True
    assert scan_text('{"sample":"hello"}')["decision"] == "ALLOW"


from types import SimpleNamespace

from app.services.policy_service import check_permission, get_docker_policy


def test_student_can_run_openclaw():
    user = SimpleNamespace(role="student")
    result = check_permission(user, "run_openclaw", "job", {})
    assert result["allow"] is True
    assert result["docker"]["network"] is False


def test_student_cannot_manage_policy():
    user = SimpleNamespace(role="student")
    result = check_permission(user, "manage_policy", "policy", {})
    assert result["allow"] is False


def test_admin_docker_policy():
    user = SimpleNamespace(role="admin")
    docker_policy = get_docker_policy(user, "run_openclaw")
    assert docker_policy["memory"] == "1024m"


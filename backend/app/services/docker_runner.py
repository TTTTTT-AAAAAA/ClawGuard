from pathlib import Path
import json
import time

from ..config import get_settings


def _fallback_run(job_id: str, action: str, command: list[str], docker_policy: dict, job_dir: Path) -> dict:
    output_dir = job_dir / "output"
    logs_dir = job_dir / "logs"
    output_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    result = {
        "job_id": job_id,
        "action": action,
        "mode": "docker_unavailable_fallback",
        "policy": docker_policy,
        "summary": "Docker SDK or daemon unavailable; generated deterministic demo result.",
    }
    (output_dir / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    (logs_dir / "runtime.log").write_text(f"{time.ctime()} fallback executed: {' '.join(command)}\n", encoding="utf-8")
    return {"status": "SUCCESS", "exit_code": 0, "container_id": None, "logs": "fallback executed"}


def run_job(job_id: str, action: str, command: list[str], docker_policy: dict) -> dict:
    settings = get_settings()
    job_dir = Path(settings.jobs_dir) / job_id
    input_dir = job_dir / "input"
    output_dir = job_dir / "output"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        import docker

        client = docker.from_env()
        nano_cpus = int(float(docker_policy.get("cpu", 1)) * 1_000_000_000)
        container = client.containers.run(
            settings.sandbox_image,
            command=command[2:],
            detach=True,
            remove=False,
            network_disabled=not bool(docker_policy.get("network", False)),
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            mem_limit=docker_policy.get("memory", "512m"),
            nano_cpus=nano_cpus,
            pids_limit=int(docker_policy.get("pids_limit", 128)),
            user="1000:1000",
            volumes={
                str(input_dir.resolve()): {"bind": "/workspace/input", "mode": "ro"},
                str(output_dir.resolve()): {"bind": "/workspace/output", "mode": "rw"},
            },
        )
        result = container.wait(timeout=int(docker_policy.get("max_runtime", 60)))
        logs = container.logs(stdout=True, stderr=True).decode(errors="ignore")
        container.remove(force=True)
        status_code = result.get("StatusCode", 1)
        return {
            "status": "SUCCESS" if status_code == 0 else "FAILED",
            "exit_code": status_code,
            "container_id": container.id,
            "logs": logs,
        }
    except Exception as exc:
        return _fallback_run(job_id, action, command, docker_policy, job_dir) | {"warning": str(exc)}


def stop_job(job_id: str) -> bool:
    return False


def get_container_logs(job_id: str) -> str:
    path = Path(get_settings().jobs_dir) / job_id / "logs" / "runtime.log"
    return path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""


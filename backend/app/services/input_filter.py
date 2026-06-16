import ipaddress
import re
from pathlib import Path

from ..config import get_settings
from ..security.sanitizer import sanitize_text


DENY_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(^|[\\/])etc[\\/]passwd"),
    re.compile(r"~[\\/]\.ssh"),
    re.compile(r"(^|[\\/])\.\.([\\/]|$)|\.\.[\\/]"),
    re.compile(r"169\.254\.169\.254"),
]
MASK_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(password|token|secret|api[_-]?key)\s*[:=]"),
]
LOCAL_NAMES = {"localhost"}
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def scan_text(text: str) -> dict:
    findings = []
    for pattern in DENY_PATTERNS:
        if pattern.search(text):
            findings.append({"level": "high", "rule": pattern.pattern})
    for pattern in MASK_PATTERNS:
        if pattern.search(text):
            findings.append({"level": "medium", "rule": pattern.pattern})
    for token in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|localhost\b", text, re.I):
        if token.lower() in LOCAL_NAMES:
            findings.append({"level": "high", "rule": "localhost"})
            continue
        try:
            ip = ipaddress.ip_address(token)
            for network in PRIVATE_NETWORKS:
                if ip in network:
                    findings.append({"level": "high", "rule": f"private_ip:{network}"})
                    break
        except ValueError:
            pass
    if any(item["level"] == "high" for item in findings):
        decision = "DENY"
    elif findings:
        decision = "MASK"
    else:
        decision = "ALLOW"
    return {"decision": decision, "findings": findings, "sanitized": sanitize_text(text)}


def scan_file(file_path: str) -> dict:
    path = Path(file_path)
    settings = get_settings()
    if path.stat().st_size > settings.upload_max_bytes:
        return {"decision": "DENY", "findings": [{"level": "high", "rule": "file_too_large"}], "sanitized": ""}
    text = path.read_text(encoding="utf-8", errors="ignore")
    return scan_text(text)


def sanitize_for_log(text: str) -> str:
    return sanitize_text(text)

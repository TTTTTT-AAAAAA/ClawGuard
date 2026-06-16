import json
from hashlib import sha256


def canonical_payload(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def body_hash(data: bytes) -> str:
    return sha256(data).hexdigest()


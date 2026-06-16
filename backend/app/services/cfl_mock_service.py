import hmac
import secrets
from hashlib import sha256


class CFLMockService:
    def __init__(self, secret: str = "mock-cfl-secret") -> None:
        self.secret = secret.encode()

    def connect(self) -> bool:
        return True

    def gen_random(self, length: int = 32) -> str:
        return secrets.token_hex(length // 2)

    def export_public_key(self, uid: str) -> dict:
        digest = sha256(f"{uid}:mock-public-key".encode()).hexdigest()
        return {"x": digest[:64], "y": digest[64:] or digest[:64]}

    def sign(self, data: bytes) -> str:
        return hmac.new(self.secret, data, sha256).hexdigest()

    def verify(self, uid: str, data: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(data), signature)

    def digest(self, data: bytes) -> str:
        return sha256(data).hexdigest()


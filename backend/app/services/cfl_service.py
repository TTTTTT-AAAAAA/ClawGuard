from pathlib import Path

from ..config import get_settings
from .cfl_mock_service import CFLMockService
from .cfl_real_service import CFLRealError, CFLRealService


class CFLService:
    def __init__(self) -> None:
        settings = get_settings()
        self.mode = settings.cfl_mode
        self.dll_path = Path(settings.cfl_dll_path)
        self.mock = CFLMockService()
        self.real = CFLRealService(self.dll_path)
        self._real_available = self.mode == "real" and self.real.available

    def connect(self) -> bool:
        if self._real_available:
            return self.real.connect()
        return self.mock.connect()

    def gen_random(self, length: int = 32) -> str:
        if self._real_available:
            return self.real.gen_random(length)
        return self.mock.gen_random(length)

    def export_public_key(self, uid: str) -> dict:
        if self._real_available:
            return self.real.export_public_key(uid)
        return self.mock.export_public_key(uid)

    def sign(self, data: bytes) -> str:
        if self._real_available:
            return self.real.sign(data)
        return self.mock.sign(data)

    def verify(self, uid: str, data: bytes, signature: str, public_key: dict | None = None) -> bool:
        if self._real_available:
            return self.real.verify(uid, data, signature, public_key=public_key)
        return self.mock.verify(uid, data, signature)

    def digest(self, data: bytes) -> str:
        if self._real_available:
            return self.real.digest(data)
        return self.mock.digest(data)

    def status(self) -> dict:
        return {
            "mode": self.mode,
            "using_real": self._real_available,
            "dll_path": str(self.dll_path),
            "real": self.real.status(),
        }

    def assert_real_ready(self) -> None:
        if self.mode != "real":
            raise CFLRealError("cfl_mode", "CLAWGUARD_CFL_MODE is not real")
        self.real.connect()

    def diagnostics(self) -> dict:
        return self.real.diagnostics()

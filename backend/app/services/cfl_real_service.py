from __future__ import annotations

import ctypes
import base64
import json
import struct
import subprocess
from pathlib import Path


ECC_COORDINATE_LEN = 64
ECC_PUBLIC_KEY_BIT_LEN = 256
UKEY_BLOB_BUFFER_LEN = 4096


class CFLRealError(RuntimeError):
    def __init__(self, operation: str, code: int | str) -> None:
        self.operation = operation
        self.code = code
        super().__init__(f"{operation} failed: {code}")


class ECCPublicKeyBlob(ctypes.Structure):
    _fields_ = [
        ("BitLen", ctypes.c_ulong),
        ("XCoordinate", ctypes.c_ubyte * ECC_COORDINATE_LEN),
        ("YCoordinate", ctypes.c_ubyte * ECC_COORDINATE_LEN),
    ]


class ECCSignatureBlob(ctypes.Structure):
    _fields_ = [
        ("r", ctypes.c_ubyte * ECC_COORDINATE_LEN),
        ("s", ctypes.c_ubyte * ECC_COORDINATE_LEN),
    ]


class CFLRealService:
    """ctypes binding for CFLClientLib.dll.

    The device/session structure is intentionally treated as an opaque buffer.
    CFL headers differ between teaching packages, while the DLL only needs a
    stable pointer to its own expected memory layout across calls.
    """

    def __init__(self, dll_path: str | Path) -> None:
        self.dll_path = Path(dll_path)
        self.helper_path = self.dll_path.parent / "cfl_helper" / "CflHelper.exe"
        self._dll: ctypes.CDLL | None = None
        self._ukey = ctypes.create_string_buffer(UKEY_BLOB_BUFFER_LEN)
        self._connected = False

    @property
    def available(self) -> bool:
        return self.dll_path.exists()

    def connect(self) -> bool:
        if self._use_helper():
            response = self._helper_call({"op": "status"})
            if not response.get("ok"):
                raise CFLRealError("CflHelper.status", response.get("error", "unknown"))
            return True
        if self._connected:
            return True
        self._load()
        code = self._dll.CFL_Connect(ctypes.byref(self._ukey))
        if code != 0:
            raise CFLRealError("CFL_Connect", code)
        self._connected = True
        return True

    def close(self) -> None:
        if self._dll and self._connected:
            self._dll.CFL_Close(ctypes.byref(self._ukey))
        self._connected = False

    def gen_random(self, length: int = 32) -> str:
        if self._use_helper():
            return str(self._helper_call({"op": "random", "length": length})["value"])
        self.connect()
        out = (ctypes.c_ubyte * length)()
        code = self._dll.CFL_GenRandom(out, ctypes.c_ulong(length), ctypes.byref(self._ukey))
        if code != 0:
            raise CFLRealError("CFL_GenRandom", code)
        return bytes(out).hex()

    def export_public_key(self, uid: str | None = None, sign_key: bool = True) -> dict:
        if self._use_helper():
            response = self._helper_call({"op": "export_public_key"})
            return {"x": response["x"], "y": response["y"]}
        self.connect()
        x = ctypes.create_string_buffer(65)
        y = ctypes.create_string_buffer(65)
        code = self._dll.CFL_ExportPublicKey(1 if sign_key else 0, x, y, ctypes.byref(self._ukey))
        if code != 0:
            raise CFLRealError("CFL_ExportPublicKey", code)
        return {"x": x.value.decode("ascii"), "y": y.value.decode("ascii")}

    def digest(self, data: bytes) -> str:
        if self._use_helper():
            return str(self._helper_call({"op": "digest", "data_b64": base64.b64encode(data).decode()})["value"])
        return self._digest_bytes(data).hex()

    def sign(self, data: bytes) -> str:
        if self._use_helper():
            return str(self._helper_call({"op": "sign", "data_b64": base64.b64encode(data).decode()})["signature"])
        self.connect()
        digest = self._digest_bytes(data)
        digest_buf = self._bytes_buffer(digest)
        signature = ECCSignatureBlob()
        code = self._dll.CFL_Sign(
            digest_buf,
            ctypes.c_ulong(len(digest)),
            ctypes.byref(signature),
            ctypes.byref(self._ukey),
        )
        if code != 0:
            raise CFLRealError("CFL_Sign", code)
        return bytes(signature.r).hex() + bytes(signature.s).hex()

    def verify(self, uid: str, data: bytes, signature: str, public_key: dict | None = None) -> bool:
        if self._use_helper():
            key = public_key or self.export_public_key(uid)
            response = self._helper_call(
                {
                    "op": "verify",
                    "data_b64": base64.b64encode(data).decode(),
                    "signature": signature,
                    "public_key_x": key["x"],
                    "public_key_y": key["y"],
                }
            )
            return bool(response.get("valid"))
        self.connect()
        key = public_key or self.export_public_key(uid)
        pubkey = self._public_key_blob(key["x"], key["y"])
        sig = self._signature_blob(signature)
        digest = self._digest_bytes(data)
        digest_buf = self._bytes_buffer(digest)
        code = self._dll.CFL_Verify(
            ctypes.byref(pubkey),
            digest_buf,
            ctypes.c_ulong(len(digest)),
            ctypes.byref(sig),
            ctypes.byref(self._ukey),
        )
        return code == 0

    def status(self) -> dict:
        info = {
            "dll_path": str(self.dll_path.resolve()) if self.dll_path.exists() else str(self.dll_path),
            "dll_exists": self.dll_path.exists(),
            "dll_arch": self._dll_architecture(),
            "python_bits": struct.calcsize("P") * 8,
            "helper_path": str(self.helper_path),
            "helper_exists": self.helper_path.exists(),
            "using_helper": self._use_helper(),
            "connected": self._connected,
        }
        if self._use_helper():
            try:
                helper = self._helper_call({"op": "status"})
                return info | {"loadable": True, "helper": helper}
            except CFLRealError as exc:
                return info | {"loadable": False, "error": str(exc)}
        if not self.dll_path.exists():
            return info | {"loadable": False}
        try:
            self._load()
            return info | {"loadable": True}
        except (OSError, CFLRealError) as exc:
            return info | {"loadable": False, "error": str(exc)}

    def diagnostics(self) -> dict:
        if self._use_helper():
            return self._helper_call({"op": "diag_export_public_key", "pin": "123456"})
        return {"ok": False, "error": "diagnostics is only implemented for helper mode"}

    def _load(self) -> None:
        if self._dll:
            return
        if not self.dll_path.exists():
            raise CFLRealError("load_dll", f"not found: {self.dll_path}")
        try:
            self._dll = ctypes.CDLL(str(self.dll_path.resolve()))
        except OSError as exc:
            raise CFLRealError("load_dll", str(exc)) from exc
        self._bind_signatures()

    def _use_helper(self) -> bool:
        return self._dll_architecture() == "x86" and struct.calcsize("P") * 8 == 64 and self.helper_path.exists()

    def _helper_call(self, payload: dict) -> dict:
        if not self.helper_path.exists():
            raise CFLRealError("CflHelper", f"helper not found: {self.helper_path}")
        completed = subprocess.run(
            [str(self.helper_path)],
            input=json.dumps(payload).encode("utf-8"),
            capture_output=True,
            cwd=str(self.helper_path.parent),
            timeout=30,
        )
        raw = completed.stdout.decode("utf-8", errors="replace").strip()
        if "{" in raw and "}" in raw:
            raw = raw[raw.find("{") : raw.rfind("}") + 1]
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        try:
            response = json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            raise CFLRealError("CflHelper", f"invalid helper response: {raw} {stderr}") from exc
        if completed.returncode != 0 or response.get("ok") is False:
            raise CFLRealError("CflHelper", response.get("error") or stderr or completed.returncode)
        return response

    def _bind_signatures(self) -> None:
        dll = self._dll
        dll.CFL_Connect.argtypes = [ctypes.c_void_p]
        dll.CFL_Connect.restype = ctypes.c_int
        dll.CFL_Close.argtypes = [ctypes.c_void_p]
        dll.CFL_Close.restype = None
        dll.CFL_GenRandom.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulong, ctypes.c_void_p]
        dll.CFL_GenRandom.restype = ctypes.c_int
        dll.CFL_ExportPublicKey.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p]
        dll.CFL_ExportPublicKey.restype = ctypes.c_int
        dll.CFL_Sign.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_ulong,
            ctypes.POINTER(ECCSignatureBlob),
            ctypes.c_void_p,
        ]
        dll.CFL_Sign.restype = ctypes.c_int
        dll.CFL_Verify.argtypes = [
            ctypes.POINTER(ECCPublicKeyBlob),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_ulong,
            ctypes.POINTER(ECCSignatureBlob),
            ctypes.c_void_p,
        ]
        dll.CFL_Verify.restype = ctypes.c_int
        dll.CFL_DigestInit.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
        ]
        dll.CFL_DigestInit.restype = ctypes.c_int
        dll.CFL_Digest.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ulong),
        ]
        dll.CFL_Digest.restype = ctypes.c_int
        if hasattr(dll, "HexToBytes"):
            dll.HexToBytes.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
            dll.HexToBytes.restype = ctypes.c_int

    def _digest_bytes(self, data: bytes) -> bytes:
        self.connect()
        handle = ctypes.c_void_p()
        code = self._dll.CFL_DigestInit(None, None, ctypes.c_ulong(0), ctypes.byref(handle), ctypes.byref(self._ukey))
        if code != 0:
            raise CFLRealError("CFL_DigestInit", code)
        data_buf = self._bytes_buffer(data)
        out_len = ctypes.c_ulong(64)
        out = (ctypes.c_ubyte * out_len.value)()
        code = self._dll.CFL_Digest(handle, data_buf, ctypes.c_ulong(len(data)), out, ctypes.byref(out_len))
        if code != 0:
            raise CFLRealError("CFL_Digest", code)
        return bytes(out[: out_len.value])

    def _public_key_blob(self, x_hex: str, y_hex: str) -> ECCPublicKeyBlob:
        blob = ECCPublicKeyBlob()
        blob.BitLen = ECC_PUBLIC_KEY_BIT_LEN
        self._hex_to_fixed_bytes(x_hex, blob.XCoordinate)
        self._hex_to_fixed_bytes(y_hex, blob.YCoordinate)
        return blob

    def _signature_blob(self, signature_hex: str) -> ECCSignatureBlob:
        cleaned = signature_hex.strip()
        if len(cleaned) not in {128, 256}:
            raise CFLRealError("parse_signature", "signature must be r+s hex with 128 or 256 chars")
        half = len(cleaned) // 2
        sig = ECCSignatureBlob()
        self._hex_to_fixed_bytes(cleaned[:half], sig.r)
        self._hex_to_fixed_bytes(cleaned[half:], sig.s)
        return sig

    def _hex_to_fixed_bytes(self, value: str, out_array) -> None:
        raw = value.strip().encode("ascii")
        if self._dll and hasattr(self._dll, "HexToBytes"):
            code = self._dll.HexToBytes(raw, ctypes.c_int(len(raw)), out_array, ctypes.c_int(ECC_COORDINATE_LEN))
            if code == 0:
                return
        decoded = bytes.fromhex(value)
        if len(decoded) > ECC_COORDINATE_LEN:
            raise CFLRealError("hex_to_bytes", "value too long")
        for i in range(ECC_COORDINATE_LEN):
            out_array[i] = 0
        start = ECC_COORDINATE_LEN - len(decoded)
        for i, byte in enumerate(decoded):
            out_array[start + i] = byte

    @staticmethod
    def _bytes_buffer(data: bytes):
        if not data:
            return (ctypes.c_ubyte * 1)(0)
        return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)

    def _dll_architecture(self) -> str | None:
        if not self.dll_path.exists():
            return None
        try:
            data = self.dll_path.read_bytes()
            offset = data.find(b"PE\0\0")
            if offset < 0:
                return "unknown"
            machine = int.from_bytes(data[offset + 4 : offset + 6], "little")
            return {0x14C: "x86", 0x8664: "x64", 0x1C0: "arm"}.get(machine, f"unknown:0x{machine:x}")
        except OSError:
            return "unknown"

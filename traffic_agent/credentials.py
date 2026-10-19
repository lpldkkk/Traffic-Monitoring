"""Store provider API keys encrypted for the current Windows user via DPAPI."""
import base64
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import tempfile


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _free(blob):
    local_free = ctypes.WinDLL("kernel32", use_last_error=True).LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p
    local_free(ctypes.cast(blob.pbData, ctypes.c_void_p))


def _protect(value):
    if os.name != "nt":
        raise RuntimeError("保存 API Key 目前仅支持 Windows；其他系统请使用环境变量")
    raw = value.encode("utf-8")
    buffer = ctypes.create_string_buffer(raw)
    incoming = _Blob(len(raw), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    outgoing = _Blob()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt.CryptProtectData.argtypes = [ctypes.POINTER(_Blob), wintypes.LPCWSTR, ctypes.c_void_p,
                                        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
    crypt.CryptProtectData.restype = wintypes.BOOL
    if not crypt.CryptProtectData(ctypes.byref(incoming), None, None, None, None, 0, ctypes.byref(outgoing)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(outgoing.pbData, outgoing.cbData)
    finally:
        _free(outgoing)


def _unprotect(value):
    if os.name != "nt":
        raise RuntimeError("读取已保存 API Key 目前仅支持 Windows")
    buffer = ctypes.create_string_buffer(value)
    incoming = _Blob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    outgoing = _Blob()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt.CryptUnprotectData.argtypes = [ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.c_void_p,
                                         ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
    crypt.CryptUnprotectData.restype = wintypes.BOOL
    if not crypt.CryptUnprotectData(ctypes.byref(incoming), None, None, None, None, 0, ctypes.byref(outgoing)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(outgoing.pbData, outgoing.cbData).decode("utf-8")
    finally:
        _free(outgoing)


class Credentials:
    def __init__(self, path):
        self.path = Path(path)

    def get(self, provider):
        if not self.path.exists():
            return ""
        data = json.loads(self.path.read_text(encoding="utf-8"))
        cipher = data.get(provider)
        return _unprotect(base64.b64decode(cipher, validate=True)) if cipher else ""

    def save(self, provider, key):
        if provider not in {"OpenAI", "DeepSeek"}:
            raise ValueError("不支持的服务商")
        if not key or key != key.strip():
            raise ValueError("API Key 不能为空或包含首尾空格")
        data = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}
        data[provider] = base64.b64encode(_protect(key)).decode("ascii")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(prefix=".credentials-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(data, stream, ensure_ascii=False)
            os.replace(temp, self.path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)


def active_key(credentials, provider):
    env = ("OPENAI_API_KEY" if provider == "OpenAI" else "DEEPSEEK_API_KEY")
    try:
        saved = credentials.get(provider)
    except (OSError, ValueError, json.JSONDecodeError):
        saved = ""
    return saved or os.getenv(env) or os.getenv("LLM_API_KEY", "")

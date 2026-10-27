"""Optional Windows current-user DPAPI storage, excluded from submission archives."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
from ctypes import wintypes


KEY_PATH = Path(__file__).resolve().parent.parent / "runtime" / "google_api_key.dpapi"


class Blob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def _crypt(data: bytes, decrypt: bool) -> bytes:
    if os.name != "nt":
        raise OSError("Local key storage requires Windows; use hidden input or an environment variable.")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    output = Blob()
    fn = crypt32.CryptUnprotectData if decrypt else crypt32.CryptProtectData
    # The second parameter is either an optional description or its output pointer;
    # passing NULL is valid for both operations.
    fn.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob),
                   ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    fn.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    # CRYPTPROTECT_UI_FORBIDDEN. No LOCAL_MACHINE flag: bound to the current user.
    if not fn(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(output)):
        raise OSError(f"Windows credential encryption/decryption failed (code {ctypes.get_last_error()})")
    try:
        return ctypes.string_at(output.data, output.size)
    finally:
        kernel32.LocalFree(output.data)


def save_key(key: str, path: Path = KEY_PATH) -> None:
    if not key.strip():
        raise ValueError("Empty key")
    encrypted = _crypt(key.strip().encode("utf-8"), decrypt=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_bytes(encrypted)
    temporary.replace(path)


def load_key(path: Path = KEY_PATH) -> str | None:
    if not path.exists():
        return None
    return _crypt(path.read_bytes(), decrypt=True).decode("utf-8")


def configured_key() -> str | None:
    return os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY") or load_key()

"""
Native Messaging host for Cerberus Password Manager (development scaffold).

WARNING: Development-only. For testing with the Firefox/Chrome extension.
Authentication: expects master password via CERB_MASTER environment variable.

Protocol: newline-free JSON messages with 4-byte little-endian length prefix.
Messages:
  {"type":"ping"}
  {"type":"list_entries"}
  {"type":"get_for_origin", "origin":"https://example.com", "include_password": false}

Responses:
  {"ok": true, "result": ...} or {"ok": false, "error": "..."}
"""
from __future__ import annotations

import json
import os
import struct
import sys
from typing import Any, Dict, List
from urllib.parse import urlparse

from cerberus.core.password_manager import PasswordManager, VaultError


def _read_msg() -> Dict[str, Any] | None:
    raw_len = sys.stdin.buffer.read(4)
    if not raw_len:
        return None
    msg_len = struct.unpack("<I", raw_len)[0]
    data = sys.stdin.buffer.read(msg_len)
    if not data:
        return None
    return json.loads(data.decode("utf-8"))


essential_fields = ["id", "website", "username", "url", "notes", "tags", "updated_at", "last_used"]


def _write_msg(obj: Dict[str, Any]) -> None:
    data = json.dumps(obj, default=str, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(data)))
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def _origin_host(origin: str) -> str:
    try:
        u = urlparse(origin)
        return u.hostname or origin
    except Exception:
        return origin


def main() -> None:
    master = os.environ.get("CERB_MASTER")
    data_dir = os.environ.get("CERB_DATA_DIR")
    pm: PasswordManager | None = None

    if master:
        try:
            pm = PasswordManager(data_dir=data_dir, master_password=master)
        except VaultError as e:
            _write_msg({"ok": False, "error": f"unlock_failed:{e}"})
            return
    else:
        # Defer unlock until first request arrives
        pm = None

    allow_remote_unlock = os.environ.get("CERB_ALLOW_REMOTE_UNLOCK") == "1"

    while True:
        msg = _read_msg()
        if msg is None:
            break
        try:
            mtype = msg.get("type")
            if mtype == "ping":
                _write_msg({"ok": True, "result": "pong"})
                continue
            if mtype == "unlock":
                if not allow_remote_unlock:
                    _write_msg({"ok": False, "error": "remote_unlock_disabled"})
                else:
                    master = msg.get("master")
                    if not master:
                        _write_msg({"ok": False, "error": "missing_master"})
                        continue
                    try:
                        pm = PasswordManager(data_dir=data_dir, master_password=master)
                        _write_msg({"ok": True, "result": "unlocked"})
                    except VaultError as e:
                        _write_msg({"ok": False, "error": f"unlock_failed:{e}"})
                continue
            if pm is None:
                _write_msg({"ok": False, "error": "locked"})
                continue
            if mtype == "list_entries":
                entries = pm.get_entries()
                slim = [
                    {
                        "id": e.id,
                        "website": e.website,
                        "username": e.username,
                        "url": e.url,
                    }
                    for e in entries
                ]
                _write_msg({"ok": True, "result": slim})
                continue
            if mtype == "get_for_origin":
                origin = msg.get("origin") or ""
                include_password = bool(msg.get("include_password", False))
                host = _origin_host(origin).lower()
                matches = []
                for e in pm.get_entries():
                    target = (e.url or e.website or "").lower()
                    if host and host in target:
                        item = {
                            "id": e.id,
                            "website": e.website,
                            "username": e.username,
                            "url": e.url,
                        }
                        if include_password:
                            item["password"] = e.password
                        matches.append(item)
                _write_msg({"ok": True, "result": matches})
                continue
            _write_msg({"ok": False, "error": f"unknown_type:{mtype}"})
        except Exception as e:
            _write_msg({"ok": False, "error": f"exception:{e}"})


if __name__ == "__main__":
    main()

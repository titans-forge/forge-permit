# SPDX-License-Identifier: Apache-2.0
"""Small local broker. Root directories and the host are trusted; workers are not."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time


class PolicyError(ValueError):
    pass


class AuditUnavailable(RuntimeError):
    """No more work may run when an audit write cannot be made durable."""


FIELDS = {"task_id", "read_paths", "export_paths", "max_file_bytes", "max_total_bytes",
          "max_files", "max_calls", "expires_at"}
LIMITS = {"max_file_bytes": 65536, "max_total_bytes": 1048576,
          "max_files": 64, "max_calls": 256}


def _filename(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise PolicyError("single_component_filename_required")
    return value


def _policy(raw, *, child=False):
    expected = FIELDS - {"task_id"} if child else FIELDS
    if not isinstance(raw, dict) or set(raw) != expected:
        raise PolicyError("policy_fields_invalid")
    value = dict(raw)
    if not child:
        value["task_id"] = _filename(raw["task_id"])
    for field in ("read_paths", "export_paths"):
        names = raw[field]
        if not isinstance(names, list) or len(names) > 64:
            raise PolicyError("policy_paths_invalid")
        value[field] = [_filename(name) for name in names]
        if len(set(names)) != len(names):
            raise PolicyError("duplicate_policy_path")
        value[field] = sorted(names)
    for field, ceiling in LIMITS.items():
        if type(raw[field]) is not int or not 0 < raw[field] <= ceiling:
            raise PolicyError(f"invalid_{field}")
    expiry = raw["expires_at"]
    if type(expiry) not in (int, float) or not math.isfinite(expiry) or expiry <= 0:
        raise PolicyError("invalid_expiry")
    return value


@dataclass
class _Capability:
    policy: dict
    identity: str
    parent: _Capability | None = None
    calls: int = 0
    files: int = 0
    exported_bytes: int = 0
    revoked: bool = False


class PermitBroker:
    def __init__(self, input_root: Path, export_root: Path, policy: dict,
                 receipt_path: Path, clock=time.time):
        self.policy = _policy(policy)
        self.clock = clock
        self._lock = threading.RLock()
        self._closed = False
        self._audit_failed = False
        self._serial = 0
        self._fds = []
        self._audit = None
        self.policy_sha256 = hashlib.sha256(json.dumps(self.policy, sort_keys=True,
                                                     separators=(",", ":")).encode()).hexdigest()
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            self._input = os.open(input_root, flags)
            self._fds.append(self._input)
            self._export = os.open(export_root, flags)
            self._fds.append(self._export)
            if os.fstat(self._input).st_ino == os.fstat(self._export).st_ino and os.fstat(self._input).st_dev == os.fstat(self._export).st_dev:
                raise PolicyError("input_and_export_roots_must_differ")
            audit_fd = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            self._audit = os.fdopen(audit_fd, "w", encoding="utf-8")
        except BaseException:
            self.close()
            raise
        self.root_token = secrets.token_urlsafe(32)
        self._capabilities = {self.root_token: _Capability(self.policy, "root")}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        with self._lock:
            if not self._closed:
                for fd in self._fds:
                    os.close(fd)
                if self._audit:
                    self._audit.close()
                self._closed = True

    def revoke(self, token):
        """Trusted operator API; it is never exposed as a worker tool."""
        with self._lock:
            self._capabilities[token].revoked = True

    def _record(self, record):
        try:
            self._audit.write(json.dumps(record, sort_keys=True, allow_nan=False) + "\n")
            self._audit.flush()
            os.fsync(self._audit.fileno())
        except (OSError, ValueError) as exc:
            self._audit_failed = True
            raise AuditUnavailable("audit_unavailable_no_further_actions") from exc

    @staticmethod
    def _ancestors(capability):
        chain = []
        while capability:
            chain.append(capability)
            capability = capability.parent
        return chain

    def request(self, request):
        with self._lock:
            if self._closed or self._audit_failed:
                raise AuditUnavailable("broker_closed_or_audit_unavailable")
            self._serial += 1
            action_id = f"action-{self._serial:04d}"
            tool = request.get("tool") if isinstance(request, dict) else None
            if not isinstance(tool, str):
                tool = None
            stamp = self.clock()
            if not isinstance(stamp, (float, int)) or not math.isfinite(stamp):
                raise AuditUnavailable("clock_unavailable")
            token = request.get("capability") if isinstance(request, dict) else None
            cap = self._capabilities.get(token) if isinstance(token, str) else None
            event = {"action_id": action_id, "task_id": self.policy["task_id"],
                     "policy_sha256": self.policy_sha256, "at": stamp,
                     "capability_id": cap.identity if cap else "unknown",
                     "tool": tool if tool in {"read_input", "export_artifact", "delegate"} else "unknown"}

            def deny(reason):
                self._record({**event, "decision": "deny", "outcome": "not_executed", "reason": reason})
                return {"ok": False, "decision": "deny", "reason": reason, "result": {}, "action_id": action_id}

            if not cap:
                return deny("unknown_capability")
            chain = self._ancestors(cap)
            if any(c.revoked for c in chain):
                return deny("revoked_capability")
            if any(stamp >= c.policy["expires_at"] for c in chain):
                return deny("expired_capability")
            if any(c.calls >= c.policy["max_calls"] for c in chain):
                return deny("call_quota_exceeded")
            for ancestor in chain:
                ancestor.calls += 1
            expected = {
                "read_input": {"capability", "tool", "path"},
                "export_artifact": {"capability", "tool", "path", "content"},
                "delegate": {"capability", "tool", "permissions"},
            }
            if tool not in expected:
                return deny("unsupported_tool")
            if set(request) != expected[tool]:
                return deny("request_fields_invalid")
            try:
                if tool == "delegate":
                    child_policy = _policy(request["permissions"], child=True)
                    if any(not set(child_policy[k]) <= set(cap.policy[k]) for k in ("read_paths", "export_paths")):
                        return deny("child_scope_widening")
                    if any(child_policy[k] > cap.policy[k] for k in (*LIMITS, "expires_at")):
                        return deny("child_limit_widening")
                    if len(chain) >= 4 or len(self._capabilities) >= 16:
                        return deny("delegation_limit")
                    child_policy["task_id"] = self.policy["task_id"]
                else:
                    path = _filename(request["path"])
                    allowed = cap.policy["read_paths" if tool == "read_input" else "export_paths"]
                    if path not in allowed:
                        return deny("path_not_permitted")
                    event["path"] = path
                if tool == "export_artifact":
                    if not isinstance(request["content"], str):
                        return deny("content_must_be_text")
                    content = request["content"].encode("utf-8")
                    if any(len(content) > c.policy["max_file_bytes"] for c in chain):
                        return deny("file_byte_quota_exceeded")
                    if any(c.exported_bytes + len(content) > c.policy["max_total_bytes"] or
                           c.files + 1 > c.policy["max_files"] for c in chain):
                        return deny("aggregate_export_quota_exceeded")
                    try:
                        os.stat(path, dir_fd=self._export, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        return deny("export_exists")
            except (PolicyError, UnicodeError, TypeError):
                return deny("invalid_permission_or_path")

            read_fd = None
            if tool == "read_input":
                try:
                    read_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._input)
                    info = os.fstat(read_fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise PolicyError("regular_single_link_input_required")
                except (OSError, PolicyError):
                    if read_fd is not None:
                        os.close(read_fd)
                    return deny("unsafe_or_unavailable_input")
            # Persist intent before reading content or mutating state.
            try:
                self._record({**event, "decision": "allow", "outcome": "pending", "reason": "policy_matched"})
            except BaseException:
                if read_fd is not None:
                    os.close(read_fd)
                raise
            try:
                if tool == "read_input":
                    with os.fdopen(read_fd, "rb") as handle:
                        data = handle.read(65537)
                        if len(data) > 65536:
                            raise PolicyError("input_too_large")
                    result = {"text": data.decode("utf-8"), "sha256": hashlib.sha256(data).hexdigest()}
                    summary = {"bytes": len(data), "sha256": result["sha256"]}
                elif tool == "delegate":
                    child_token = secrets.token_urlsafe(32)
                    identity = f"child-{len(self._capabilities)}"
                    self._capabilities[child_token] = _Capability(child_policy, identity, cap)
                    result = {"capability": child_token}
                    summary = {"child_id": identity}
                else:
                    # Reserve the aggregate quota before file creation; failed attempts stay charged.
                    for ancestor in chain:
                        ancestor.exported_bytes += len(content)
                        ancestor.files += 1
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=self._export)
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(content)
                        handle.flush()
                        os.fsync(handle.fileno())
                    result = {"path": path, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                    summary = result
            except (OSError, PolicyError, UnicodeError) as exc:
                reason = str(exc) if isinstance(exc, PolicyError) else type(exc).__name__
                self._record({**event, "decision": "allow", "outcome": "failed", "reason": reason})
                return {"ok": False, "decision": "allow", "reason": reason,
                        "result": {}, "action_id": action_id}
            self._record({**event, "decision": "allow", "outcome": "completed", "reason": "completed", "summary": summary})
            return {"ok": True, "decision": "allow", "reason": "completed", "result": result, "action_id": action_id}

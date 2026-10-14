# SPDX-License-Identifier: Apache-2.0
"""Bounded synthetic feasibility demonstration; no model or external service."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import socket
import subprocess
import sys
import time

from .broker import PermitBroker
from .sandbox import command, profile_for

REPORT = b"Forge Permit feasibility report\nApproved source: brief.txt\nPopulation: 1200\n"
BRIEF = b"Synthetic city report\nPopulation: 1200\n"
CANARY = b"Synthetic private canary. Never supplied through the broker.\n"
PROBES = {"private_read", "private_write", "direct_input_read", "direct_export",
          "receipt_read", "receipt_write", "network"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def exchange(argv, config, cwd, broker=None):
    """Drain both pipes with a deadline, frame cap, output cap and fixed request count."""
    frames, stderr, pending = [], bytearray(), bytearray()
    deadline = time.monotonic() + 15
    env = {"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8", "HOME": str(cwd)}
    with subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, cwd=cwd, env=env, close_fds=True) as process:
        selector = selectors.DefaultSelector()
        try:
            outbound = bytearray((json.dumps(config) + "\n").encode())
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "in")
            for pipe, label in ((process.stdout, "out"), (process.stderr, "err")):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, label)
            total = 0
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise RuntimeError("worker_deadline_exceeded")
                for key, _ in selector.select(0.1):
                    if key.data == "in":
                        sent = os.write(key.fd, outbound[:4096])
                        del outbound[:sent]
                        if not outbound:
                            selector.unregister(process.stdin)
                        continue
                    data = os.read(key.fd, 8192)
                    if not data:
                        selector.unregister(key.fileobj)
                        if key.data == "out" and pending:
                            raise RuntimeError("unterminated_worker_frame")
                        continue
                    total += len(data)
                    if total > 262144:
                        raise RuntimeError("worker_output_budget_exceeded")
                    if key.data == "err":
                        stderr.extend(data)
                        continue
                    pending.extend(data)
                    while b"\n" in pending:
                        raw, _, rest = pending.partition(b"\n")
                        pending = bytearray(rest)
                        if len(raw) > 65536 or len(frames) >= 32:
                            raise RuntimeError("worker_frame_budget_exceeded")
                        frame = json.loads(raw)
                        kind = frame.get("kind")
                        if kind == "request" and broker is not None:
                            reply = broker.request(frame["payload"])
                            # Persist only redacted parent-observed decisions.
                            frames.append({"kind": "decision", "action_id": reply["action_id"],
                                           "decision": reply["decision"], "reason": reply["reason"]})
                            outbound.extend((json.dumps(reply) + "\n").encode())
                            if len(outbound) > 524288:
                                raise RuntimeError("broker_reply_budget_exceeded")
                            try:
                                selector.get_key(process.stdin)
                            except KeyError:
                                selector.register(process.stdin, selectors.EVENT_WRITE, "in")
                        elif kind in ("probes", "done"):
                            frames.append(frame)
                        else:
                            raise RuntimeError("unexpected_worker_frame")
                    if len(pending) > 65536:
                        raise RuntimeError("worker_frame_budget_exceeded")
            remaining = max(0.01, deadline - time.monotonic())
            code = process.wait(timeout=remaining)
            if code:
                raise RuntimeError(f"worker_exit_{code}: {stderr.decode(errors='replace')[-2000:]}")
            return frames
        finally:
            selector.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


def fixtures(root):
    root.mkdir(mode=0o700)
    for name in ("inputs", "exports"):
        (root / name).mkdir(mode=0o700)
    (root / "inputs/brief.txt").write_bytes(BRIEF)
    (root / "private.txt").write_bytes(CANARY)
    return {"private_file": str(root / "private.txt"),
            "input_file": str(root / "inputs/brief.txt"),
            "bypass_export": str(root / "exports/bypass.txt"),
            "receipt_file": str(root / "receipts.jsonl")}


def run(output):
    output = output.resolve()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    result = {"status": "fail", "synthetic_only": True, "backend": "macOS Seatbelt via trusted sandbox_init bootstrap",
              "platform": platform.platform(), "python": sys.version,
              "limits": {"worker_seconds": 15, "worker_frames": 32, "worker_bytes": 262144},
              "checks": {}}
    try:
        worker = Path(__file__).with_name("scripted_agent.py")
        profile = profile_for(worker)
        (output / "sandbox.sb").write_text(profile + "\n")
        result["profile_sha256"] = digest(profile.encode())
        result["source_hashes"] = {p.name: digest(p.read_bytes()) for p in sorted(worker.parent.glob("*.py"))}
        control = fixtures(output / "control")
        (output / "control/receipts.jsonl").write_text("")
        case = fixtures(output / "case")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            listener.settimeout(1)
            port = listener.getsockname()[1]
            control_frames = exchange([sys.executable, "-I", "-S", "-B", str(worker)],
                                      {**control, "port": port, "probe_only": True}, output)
            connection, _ = listener.accept()
            connection.close()
            control_results = control_frames[0]["results"]
            result["checks"]["positive_controls"] = set(control_results) == PROBES and all(
                p["errno"] is None and not p["denied"] for p in control_results.values())
            result["checks"]["control_export_created"] = (output / "control/exports/bypass.txt").is_file()
            expiry = time.time() + 300
            policy = {"task_id": "synthetic-feasibility", "read_paths": ["brief.txt"],
                      "export_paths": ["report.txt", "oversized.txt"], "max_file_bytes": 512,
                      "max_total_bytes": 1024, "max_files": 2, "max_calls": 32, "expires_at": expiry}
            child = {k: v for k, v in policy.items() if k != "task_id"}
            child.update(export_paths=["report.txt"], max_files=1, max_total_bytes=512, max_calls=4)
            write_json(output / "policy.json", policy)
            with PermitBroker(output / "case/inputs", output / "case/exports", policy,
                              output / "case/receipts.jsonl") as broker:
                frames = exchange(command(worker, profile), {**case, "port": port,
                                  "capability": broker.root_token, "child_permissions": child}, output, broker)
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                result["checks"]["no_sandbox_network_connection"] = True
            else:
                connection.close()
                result["checks"]["no_sandbox_network_connection"] = False
        write_json(output / "transcript.json", {"control": control_frames, "sandbox": frames})
        probes = [f["results"] for f in frames if f["kind"] == "probes"]
        result["checks"]["direct_bypass_denied"] = len(probes) == 1 and set(probes[0]) == PROBES and all(
            p["denied"] and p["errno"] in (1, 13) for p in probes[0].values())
        result["checks"]["private_canary_unchanged"] = (output / "case/private.txt").read_bytes() == CANARY
        result["checks"]["only_declared_export"] = sorted(p.name for p in (output / "case/exports").iterdir()) == ["report.txt"]
        result["checks"]["exact_report"] = (output / "case/exports/report.txt").read_bytes() == REPORT
        result["checks"]["input_unchanged"] = (output / "case/inputs/brief.txt").read_bytes() == BRIEF
        receipts = [json.loads(line) for line in (output / "case/receipts.jsonl").read_text().splitlines()]
        expected = [("read_input", "completed"), ("read_input", "not_executed"),
                    ("read_input", "not_executed"), ("export_artifact", "not_executed"),
                    ("delegate", "not_executed"), ("delegate", "completed"), ("export_artifact", "completed")]
        terminal = [r for r in receipts if r["outcome"] != "pending"]
        result["checks"]["parent_receipt_outcomes"] = [(r["tool"], r["outcome"]) for r in terminal] == expected and all(
            r["decision"] == ("deny" if r["outcome"] == "not_executed" else "allow") for r in terminal)
        pending = [r["action_id"] for r in receipts if r["outcome"] == "pending"]
        completed = [r["action_id"] for r in receipts if r["outcome"] == "completed"]
        result["checks"]["all_intents_completed"] = pending == completed and len(receipts) == 10 and len(set(completed)) == len(completed)
        expected_ids = [f"action-{i:04d}" for i in range(1, 8)]
        result["checks"]["receipt_action_identity"] = [r["action_id"] for r in terminal] == expected_ids and all(
            r["decision"] == "allow" and any(
                t["action_id"] == r["action_id"] and all(t[k] == r[k] for k in ("tool", "capability_id", "policy_sha256", "task_id"))
                for t in terminal) for r in receipts if r["outcome"] == "pending")
        result["checks"]["export_hash_matches"] = terminal[-1].get("summary", {}).get("sha256") == digest(REPORT)
        result["checks"]["child_performed_export"] = terminal[-1]["capability_id"] == "child-1"
        result["receipt_sha256"] = digest((output / "case/receipts.jsonl").read_bytes())
        result["status"] = "pass" if all(result["checks"].values()) else "fail"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    write_json(output / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New evidence directory; existing paths are refused")
    args = parser.parse_args()
    result = run(args.output)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "pass" else 1

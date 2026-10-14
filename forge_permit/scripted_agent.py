# SPDX-License-Identifier: Apache-2.0
"""Synthetic worker: attempts direct bypass, then uses the broker's JSONL channel."""
import json
import os
import socket
import sys


def send(payload):
    print(json.dumps(payload), flush=True)


def receive():
    line = sys.stdin.buffer.readline(100000)
    if not line or len(line) >= 100000:
        raise RuntimeError("invalid_frame")
    return json.loads(line)


def probe(function):
    try:
        function()
        return {"denied": False, "errno": None}
    except OSError as exc:
        return {"denied": exc.errno in (1, 13), "errno": exc.errno}


def read_file(path):
    with open(path, "rb") as handle:
        handle.read(1)


def write_access(path):
    fd = os.open(path, os.O_WRONLY)
    os.close(fd)


def create_file(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)


def main():
    config = receive()
    probes = {
        "private_read": probe(lambda: read_file(config["private_file"])),
        "private_write": probe(lambda: write_access(config["private_file"])),
        "direct_input_read": probe(lambda: read_file(config["input_file"])),
        "direct_export": probe(lambda: create_file(config["bypass_export"])),
        "receipt_read": probe(lambda: read_file(config["receipt_file"])),
        "receipt_write": probe(lambda: write_access(config["receipt_file"])),
        "network": probe(lambda: socket.create_connection(("127.0.0.1", config["port"]), timeout=1).close()),
    }
    send({"kind": "probes", "results": probes})
    if config.get("probe_only"):
        return
    token = config["capability"]

    def call(tool, **fields):
        send({"kind": "request", "payload": {"capability": token, "tool": tool, **fields}})
        return receive()

    outcomes = {}
    read = call("read_input", path="brief.txt")
    outcomes["allowed_read"] = read["ok"] and read["result"].get("text", "").startswith("Synthetic city report")
    outcomes["undeclared_read_denied"] = not call("read_input", path="private.txt")["ok"]
    outcomes["traversal_denied"] = not call("read_input", path="../private.txt")["ok"]
    outcomes["oversized_export_denied"] = not call("export_artifact", path="oversized.txt", content="x" * 513)["ok"]
    permissions = dict(config["child_permissions"])
    permissions["read_paths"] = ["brief.txt", "private.txt"]
    outcomes["child_widening_denied"] = not call("delegate", permissions=permissions)["ok"]
    delegated = call("delegate", permissions=config["child_permissions"])
    outcomes["narrow_child_allowed"] = delegated["ok"]
    if delegated["ok"]:
        token = delegated["result"]["capability"]
        report = "Forge Permit feasibility report\nApproved source: brief.txt\nPopulation: 1200\n"
        export = call("export_artifact", path="report.txt", content=report)
        outcomes["allowed_export"] = export["ok"] and export["result"].get("bytes") == len(report.encode())
    else:
        outcomes["allowed_export"] = False
    send({"kind": "done", "outcomes": outcomes})


if __name__ == "__main__":
    main()

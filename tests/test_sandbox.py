# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from forge_permit.broker import AuditUnavailable, PermitBroker
from forge_permit.sandbox import BackendUnavailable, profile_for


class FailClosedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "inputs").mkdir()
        (self.root / "exports").mkdir()
        self.policy = dict(task_id="test", read_paths=[], export_paths=["report.txt"],
                           max_file_bytes=32, max_total_bytes=32, max_files=1,
                           max_calls=4, expires_at=time.time()+60)

    def broker(self):
        broker = PermitBroker(self.root / "inputs", self.root / "exports", self.policy, self.root / "receipts.jsonl")
        self.addCleanup(broker.close)
        return broker

    def test_audit_failure_prevents_action_and_future_actions(self):
        broker = self.broker()
        request = dict(capability=broker.root_token, tool="export_artifact", path="report.txt", content="ok")
        with patch("forge_permit.broker.os.fsync", side_effect=OSError("disk failure")):
            with self.assertRaises(AuditUnavailable):
                broker.request(request)
        self.assertFalse((self.root / "exports/report.txt").exists())
        with self.assertRaises(AuditUnavailable):
            broker.request(request)

    def test_parent_revocation_applies_to_child(self):
        broker = self.broker()
        child = broker.request(dict(capability=broker.root_token, tool="delegate",
                               permissions={k:v for k,v in self.policy.items() if k != "task_id"}))
        broker.revoke(broker.root_token)
        result = broker.request(dict(capability=child["result"]["capability"],
                                tool="export_artifact", path="report.txt", content="ok"))
        self.assertEqual(result["reason"], "revoked_capability")
        self.assertFalse((self.root / "exports/report.txt").exists())

    def test_unsupported_backend_does_not_fallback(self):
        with patch("forge_permit.sandbox.platform.system", return_value="Linux"):
            with self.assertRaises(BackendUnavailable):
                profile_for(Path(__file__))

    def test_existing_receipts_are_never_overwritten(self):
        path = self.root / "receipts.jsonl"
        path.write_text("existing evidence")
        with self.assertRaises(FileExistsError):
            self.broker()
        self.assertEqual(path.read_text(), "existing evidence")

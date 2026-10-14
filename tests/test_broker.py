"""Contract tests for the isolated Forge Permit broker prototype."""

import hashlib
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from forge_permit.broker import PermitBroker, PolicyError


class BrokerTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.input_root = self.base / "protected-input"
        self.export_root = self.base / "protected-export"
        self.receipt_dir = self.base / "protected-receipts"
        self.input_root.mkdir()
        self.export_root.mkdir()
        self.receipt_dir.mkdir()
        self._receipt_number = 0
        self.policy = self.make_policy()

    @staticmethod
    def make_policy(**overrides):
        policy = {
            "task_id": "synthetic-task",
            "read_paths": ["source.txt"],
            "export_paths": ["report.txt", "one.txt", "two.txt"],
            "max_file_bytes": 64,
            "max_total_bytes": 128,
            "max_files": 4,
            "max_calls": 20,
            "expires_at": 2000.0,
        }
        policy.update(overrides)
        return policy

    def broker(self, policy=None, **kwargs):
        self._receipt_number += 1
        receipt_path = self.receipt_dir / f"events-{self._receipt_number}.jsonl"
        broker = PermitBroker(
            input_root=self.input_root,
            export_root=self.export_root,
            policy=self.policy if policy is None else policy,
            receipt_path=receipt_path,
            clock=lambda: 1000.0,
            **kwargs,
        )
        self.last_receipt_path = receipt_path
        return broker

    def request(self, broker, capability, tool, **fields):
        return broker.request(
            {"capability": capability, "tool": tool, **fields}
        )

    def assert_denied(self, response):
        self.assertIs(response["ok"], False)
        self.assertEqual(response["decision"], "deny")
        self.assertIsInstance(response["reason"], str)
        self.assertTrue(response["reason"].strip())

    def test_read_and_exact_bounded_export(self):
        source = "Synthetic input\n"
        report = "Bounded synthetic report\n"
        (self.input_root / "source.txt").write_text(source, encoding="utf-8")

        with self.broker() as broker:
            token = broker.root_token
            read = self.request(
                broker, token, "read_input", path="source.txt"
            )
            self.assertTrue(read["ok"])
            self.assertEqual(read["decision"], "allow")
            self.assertEqual(read["result"]["text"], source)
            self.assertEqual(
                read["result"]["sha256"],
                hashlib.sha256(source.encode("utf-8")).hexdigest(),
            )

            exported = self.request(
                broker,
                token,
                "export_artifact",
                path="report.txt",
                content=report,
            )
            self.assertTrue(exported["ok"])
            self.assertEqual(exported["decision"], "allow")
            self.assertEqual(
                (self.export_root / "report.txt").read_text(encoding="utf-8"),
                report,
            )
            self.assertEqual(exported["result"]["path"], "report.txt")
            self.assertEqual(exported["result"]["bytes"], len(report.encode()))
            self.assertEqual(
                exported["result"]["sha256"],
                hashlib.sha256(report.encode("utf-8")).hexdigest(),
            )

    def test_unknown_and_expired_capabilities_are_denied(self):
        (self.input_root / "source.txt").write_text("synthetic", encoding="utf-8")
        with self.broker() as broker:
            unknown = self.request(
                broker, "not-a-capability", "read_input", path="source.txt"
            )
            self.assert_denied(unknown)

            expired_policy = self.make_policy(expires_at=999.0)
            with self.broker(expired_policy) as expired:
                denied = self.request(
                    expired,
                    expired.root_token,
                    "read_input",
                    path="source.txt",
                )
                self.assert_denied(denied)

    def test_undeclared_path_traversal_and_non_read_tool_are_denied(self):
        (self.input_root / "source.txt").write_text("safe", encoding="utf-8")
        (self.base / "outside.txt").write_text("outside secret", encoding="utf-8")
        with self.broker() as broker:
            for path in ("undeclared.txt", "../outside.txt", "nested/source.txt"):
                with self.subTest(path=path):
                    response = self.request(
                        broker,
                        broker.root_token,
                        "read_input",
                        path=path,
                    )
                    self.assert_denied(response)

            unsupported = self.request(
                broker, broker.root_token, "shell", command="echo no"
            )
            self.assert_denied(unsupported)

    def test_unhashable_tool_values_are_denied_without_raising(self):
        with self.broker() as broker:
            for tool in ([], {"name": "read_input"}):
                with self.subTest(tool=tool):
                    response = broker.request(
                        {"capability": broker.root_token, "tool": tool}
                    )
                    self.assert_denied(response)

    def test_symlink_and_hardlink_inputs_are_denied(self):
        target = self.base / "outside-source.txt"
        target.write_text("external synthetic content", encoding="utf-8")
        (self.input_root / "source.txt").symlink_to(target)
        with self.broker() as broker:
            response = self.request(
                broker,
                broker.root_token,
                "read_input",
                path="source.txt",
            )
            self.assert_denied(response)

        (self.input_root / "source.txt").unlink()
        try:
            os.link(target, self.input_root / "source.txt")
        except (NotImplementedError, OSError) as exc:
            self.skipTest("hard links unavailable in this test filesystem: " + str(exc))
        with self.broker() as broker:
            response = self.request(
                broker,
                broker.root_token,
                "read_input",
                path="source.txt",
            )
            self.assert_denied(response)

    def test_existing_export_is_preserved_and_denied(self):
        target = self.export_root / "report.txt"
        target.write_text("preserve this", encoding="utf-8")
        with self.broker() as broker:
            response = self.request(
                broker,
                broker.root_token,
                "export_artifact",
                path="report.txt",
                content="replacement",
            )
        self.assert_denied(response)
        self.assertEqual(target.read_text(encoding="utf-8"), "preserve this")

    def test_utf8_byte_limit_is_checked_before_creating_export(self):
        policy = self.make_policy(max_file_bytes=3)
        target = self.export_root / "report.txt"
        with self.broker(policy) as broker:
            response = self.request(
                broker,
                broker.root_token,
                "export_artifact",
                path="report.txt",
                content="éé",  # Two characters, four UTF-8 bytes.
            )
        self.assert_denied(response)
        self.assertFalse(target.exists())

    def test_policy_rejects_missing_and_extra_fields(self):
        missing = dict(self.policy)
        del missing["max_calls"]
        extra = dict(self.policy, unexpected=True)
        for candidate in (missing, extra):
            with self.subTest(candidate=candidate):
                with self.assertRaises(PolicyError):
                    self.broker(candidate)

    def test_child_cannot_widen_any_parent_bound(self):
        widening_cases = (
            {"read_paths": ["source.txt", "extra.txt"]},
            {"export_paths": ["report.txt", "extra.txt"]},
            {"max_file_bytes": 65},
            {"max_total_bytes": 129},
            {"max_files": 5},
            {"max_calls": 21},
            {"expires_at": 2001.0},
        )
        with self.broker() as broker:
            for widening in widening_cases:
                with self.subTest(widening=widening):
                    permissions = {
                        "read_paths": ["source.txt"],
                        "export_paths": ["report.txt"],
                        "max_file_bytes": 64,
                        "max_total_bytes": 128,
                        "max_files": 4,
                        "max_calls": 20,
                        "expires_at": 2000.0,
                    }
                    permissions.update(widening)
                    response = self.request(
                        broker,
                        broker.root_token,
                        "delegate",
                        permissions=permissions,
                    )
                    self.assert_denied(response)
                    self.assertFalse(response.get("result", {}).get("capability"))

    def test_children_share_aggregate_ancestor_quotas(self):
        parent_policy = self.make_policy(
            max_file_bytes=8,
            max_total_bytes=6,
            max_files=2,
            max_calls=10,
            export_paths=["one.txt", "two.txt"],
        )
        with self.broker(parent_policy) as broker:
            child_permissions = {
                "read_paths": ["source.txt"],
                "export_paths": ["one.txt", "two.txt"],
                "max_file_bytes": 8,
                "max_total_bytes": 6,
                "max_files": 2,
                "max_calls": 5,
                "expires_at": 1500.0,
            }
            delegated = self.request(
                broker,
                broker.root_token,
                "delegate",
                permissions=child_permissions,
            )
            self.assertTrue(delegated["ok"])
            child = delegated["result"]["capability"]
            first = self.request(
                broker,
                child,
                "export_artifact",
                path="one.txt",
                content="1234",
            )
            second = self.request(
                broker,
                child,
                "export_artifact",
                path="two.txt",
                content="5678",
            )
            self.assertTrue(first["ok"])
            self.assert_denied(second)
            self.assertFalse((self.export_root / "two.txt").exists())

    def test_delegation_does_not_reset_parent_call_budget(self):
        parent_policy = self.make_policy(max_calls=2)
        with self.broker(parent_policy) as broker:
            child_permissions = {
                "read_paths": ["source.txt"],
                "export_paths": ["report.txt"],
                "max_file_bytes": 32,
                "max_total_bytes": 32,
                "max_files": 1,
                "max_calls": 2,
                "expires_at": 1500.0,
            }
            child_result = self.request(
                broker,
                broker.root_token,
                "delegate",
                permissions=child_permissions,
            )
            self.assertTrue(child_result["ok"])
            child = child_result["result"]["capability"]

            grandchild_result = self.request(
                broker,
                child,
                "delegate",
                permissions=child_permissions,
            )
            self.assertTrue(grandchild_result["ok"])
            grandchild = grandchild_result["result"]["capability"]

            exhausted = self.request(
                broker,
                grandchild,
                "export_artifact",
                path="report.txt",
                content="not written",
            )
            self.assert_denied(exhausted)
            self.assertFalse((self.export_root / "report.txt").exists())

    def test_concurrent_exports_cannot_exceed_shared_total_quota(self):
        policy = self.make_policy(
            max_file_bytes=4,
            max_total_bytes=4,
            max_files=4,
            export_paths=["one.txt", "two.txt"],
        )
        barrier = threading.Barrier(3)
        responses = []
        with self.broker(policy) as broker:
            def export(path):
                barrier.wait()
                responses.append(
                    self.request(
                        broker,
                        broker.root_token,
                        "export_artifact",
                        path=path,
                        content="1234",
                    )
                )

            threads = [
                threading.Thread(target=export, args=(name,))
                for name in ("one.txt", "two.txt")
            ]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive(), "export thread did not finish")

        self.assertEqual(len(responses), 2)
        self.assertEqual(sum(response["ok"] for response in responses), 1)
        self.assertEqual(
            sum(path.stat().st_size for path in self.export_root.iterdir()), 4
        )

    def test_receipts_record_denial_and_lifecycle_without_secrets_or_content(self):
        secret_content = "highly-sensitive synthetic payload"
        (self.input_root / "source.txt").write_text(secret_content, encoding="utf-8")
        with self.broker() as broker:
            receipt_path = self.last_receipt_path
            token = broker.root_token
            denied = self.request(
                broker,
                token,
                "read_input",
                path="../outside.txt",
            )
            self.assert_denied(denied)
            allowed = self.request(
                broker,
                token,
                "export_artifact",
                path="report.txt",
                content=secret_content,
            )
            self.assertTrue(allowed["ok"])

        records = [
            json.loads(line)
            for line in receipt_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertGreaterEqual(len(records), 3)
        denied_records = [record for record in records if record.get("decision") == "deny"]
        self.assertTrue(denied_records)
        self.assertTrue(
            any(record.get("outcome") == "not_executed" for record in denied_records)
        )
        allowed_records = [record for record in records if record.get("decision") == "allow"]
        self.assertTrue(allowed_records)
        pending = [record for record in allowed_records if record.get("outcome") == "pending"]
        terminal = [
            record
            for record in allowed_records
            if record.get("outcome") in {"completed", "failed"}
        ]
        self.assertTrue(pending)
        self.assertTrue(terminal)
        self.assertEqual(pending[0]["action_id"], terminal[0]["action_id"])
        self.assertNotIn("intent", pending[0])
        receipt_text = receipt_path.read_text(encoding="utf-8")
        self.assertNotIn(token, receipt_text)
        self.assertNotIn(secret_content, receipt_text)


if __name__ == "__main__":
    unittest.main()

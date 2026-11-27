import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import tool_executor

from policy_loader import PolicyLoader
from policy_manager import PolicyManager


class AdvancedSecurityTests(unittest.TestCase):

    def setUp(self):

        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.path = (
            Path(self.temp.name) / "test_policies.json"
        )

        self.data = PolicyLoader().policy_data
        self.save_policies()

        loader_patch = patch(
            "policy_engine.PolicyLoader",
            side_effect=lambda: PolicyLoader(self.path)
        )

        loader_patch.start()
        self.addCleanup(loader_patch.stop)

        self.manager = PolicyManager()

        manager_patch = patch.object(
            tool_executor,
            "policy_manager",
            self.manager
        )

        manager_patch.start()
        self.addCleanup(manager_patch.stop)

    def save_policies(self):

        self.path.write_text(
            json.dumps(self.data),
            encoding="utf-8"
        )

    def add_policy(self, decision, resource, priority):

        self.data["policies"].append({
            "policy_id": "TEST-001",
            "name": "Security Test Policy",
            "action": "read_file",
            "resource": resource,
            "decision": decision,
            "enabled": True,
            "priority": priority
        })

        self.save_policies()

        self.assertTrue(
            self.manager.reload_policies()
        )

    # TEST 1: Authorized execution
    def test_authorized_execution(self):

        result = tool_executor.execute_tool(
            "read_file",
            {"filename": "public_report.txt"}
        )

        self.assertEqual(result["status"], "SUCCESS")
        self.assertTrue(result["executed"])

    # TEST 2: Deny overrides allow
    def test_policy_conflict(self):

        self.add_policy(
            "BLOCK", "public_report.txt", 1
        )

        with patch.object(
            tool_executor,
            "_execute_tool_unchecked"
        ) as executor:

            result = tool_executor.execute_tool(
                "read_file",
                {"filename": "public_report.txt"}
            )

            self.assertEqual(
                result["status"], "BLOCKED"
            )

            executor.assert_not_called()

    # TEST 3: Approval requirement
    def test_review_prevents_execution(self):

        self.add_policy(
            "REVIEW", "public_report.txt", 200
        )

        with patch.object(
            tool_executor,
            "_execute_tool_unchecked"
        ) as executor:

            result = tool_executor.execute_tool(
                "read_file",
                {"filename": "public_report.txt"}
            )

            self.assertEqual(
                result["status"], "BLOCKED"
            )

            executor.assert_not_called()

    # TEST 4: Invalid policy configuration
    def test_invalid_policy(self):

        self.path.write_text(
            "INVALID JSON",
            encoding="utf-8"
        )

        self.assertFalse(
            self.manager.reload_policies()
        )

        result = tool_executor.execute_tool(
            "read_file",
            {"filename": "public_report.txt"}
        )

        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["executed"])

    # TEST 5: Unknown role
    def test_unknown_role(self):

        result = self.manager.evaluate(
            "unknown",
            "read_file",
            "public_report.txt"
        )

        self.assertEqual(result["decision"], "BLOCK")

    # TEST 6: Privilege escalation
    def test_privilege_escalation(self):

        result = self.manager.evaluate(
            "guest",
            "delete_record",
            "database"
        )

        self.assertEqual(result["decision"], "BLOCK")

    # TEST 7: Sandbox defense
    def test_sandbox_protection(self):

        self.add_policy(
            "ALLOW", "private_report.txt", 500
        )

        result = tool_executor.execute_tool(
            "read_file",
            {"filename": "private_report.txt"}
        )

        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["executed"])

    # TEST 8: Policy recovery
    def test_policy_recovery(self):

        self.path.write_text(
            "INVALID JSON",
            encoding="utf-8"
        )

        self.assertFalse(
            self.manager.reload_policies()
        )

        self.save_policies()

        self.assertTrue(
            self.manager.reload_policies()
        )

        result = self.manager.evaluate(
            "user",
            "read_file",
            "public_report.txt"
        )

        self.assertEqual(result["decision"], "ALLOW")


if __name__ == "__main__":

    print("\n===== AgentShield Advanced Security Tests =====")

    unittest.main(verbosity=2)

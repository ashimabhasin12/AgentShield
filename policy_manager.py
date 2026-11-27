import json
from pathlib import Path
from threading import RLock
from tempfile import TemporaryDirectory
from unittest.mock import patch

from policy_engine import PolicyEngine
from policy_loader import PolicyLoader


class PolicyManager:

    def __init__(self):

        self.lock = RLock()
        self.engine = None

        self.reload_policies()

    def reload_policies(self):

        with self.lock:

            try:
                new_engine = PolicyEngine()

                self.engine = new_engine

                print("[SUCCESS] Policies reloaded.")
                return True

            except Exception as error:

                self.engine = None

                print(f"[ERROR] Reload failed: {error}")
                print("[SECURITY] Default-deny activated.")

                return False

    def get_version(self):

        with self.lock:

            if self.engine is None:
                return None

            return self.engine.loader.get_policy_version()

    def evaluate(self, role, action, resource):

        with self.lock:

            if self.engine is None:

                return {
                    "decision": "BLOCK",
                    "reason": "No valid security configuration",
                    "policy_id": None
                }

            return self.engine.evaluate(
                role, action, resource
            )


if __name__ == "__main__":

    print("\n===== AgentShield Policy Manager =====\n")

    original = PolicyLoader().policy_data

    # Test updates using a temporary configuration.
    # Production policy files remain unchanged.

    with TemporaryDirectory() as directory:

        path = Path(directory) / "test_policies.json"

        path.write_text(
            json.dumps(original),
            encoding="utf-8"
        )

        with patch(
            "policy_engine.PolicyLoader",
            side_effect=lambda: PolicyLoader(path)
        ):

            manager = PolicyManager()

            print("Current Version:", manager.get_version())

            before = manager.evaluate(
                "analyst",
                "generate_report",
                "sales_data"
            )

            print("Before Update:", before["decision"])

            assert before["decision"] == "BLOCK"

            original["policy_version"] = "1.1.0"

            original["policies"].append({
                "policy_id": "POL-004",
                "name": "Authorized Report Generation",
                "action": "generate_report",
                "resource": "sales_data",
                "decision": "ALLOW",
                "enabled": True,
                "priority": 100
            })

            path.write_text(
                json.dumps(original),
                encoding="utf-8"
            )

            assert manager.reload_policies()

            print("Updated Version:", manager.get_version())

            after = manager.evaluate(
                "analyst",
                "generate_report",
                "sales_data"
            )

            print("After Update:", after["decision"])

            assert after["decision"] == "ALLOW"

            # Test an invalid configuration.

            path.write_text(
                "INVALID JSON",
                encoding="utf-8"
            )

            assert not manager.reload_policies()

            result = manager.evaluate(
                "analyst",
                "generate_report",
                "sales_data"
            )

            print("Invalid Policy Test:", result["decision"])

            assert result["decision"] == "BLOCK"

            # Restore valid configuration.

            path.write_text(
                json.dumps(original),
                encoding="utf-8"
            )

            assert manager.reload_policies()

            recovered = manager.evaluate(
                "analyst",
                "generate_report",
                "sales_data"
            )

            assert recovered["decision"] == "ALLOW"

            print("Recovery Test: PASSED")

    print("\nRuntime Policy Update Test: PASSED")
    print("Fail-Closed Security Test: PASSED")
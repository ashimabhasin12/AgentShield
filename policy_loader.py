import json
from pathlib import Path


class PolicyLoader:

    def __init__(self, policy_path=None):
        self.policy_path = (
            Path(policy_path) if policy_path else
            Path(__file__).resolve().parent
            / "policies"
            / "security_policies.json"
        )

        self.policy_data = self.load_policies()

    def load_policies(self):
        try:
            with open(self.policy_path, "r", encoding="utf-8") as file:
                data = json.load(file)

            if not isinstance(data, dict):
                raise ValueError("Invalid policy configuration.")

            if not isinstance(data.get("policies"), list):
                raise ValueError("Missing or invalid policies list.")

            print("[SUCCESS] Security policies loaded.")
            return data

        except (OSError, ValueError) as error:
            raise RuntimeError(
                f"Policy loading failed: {error}"
            ) from error

    def get_active_policies(self):
        return [
            policy for policy in self.policy_data["policies"]
            if policy.get("enabled") is True
        ]

    def get_policy_version(self):
        return self.policy_data.get("policy_version", "Unknown")

    def get_default_decision(self):
        return self.policy_data.get("default_decision", "BLOCK")


if __name__ == "__main__":

    loader = PolicyLoader()

    print("\n===== AgentShield Policy Loader =====")
    print("Policy Version:", loader.get_policy_version())
    print("Default Decision:", loader.get_default_decision())

    active_policies = loader.get_active_policies()

    print("Active Policies:", len(active_policies))

    for policy in active_policies:
        print(
            f"{policy['policy_id']} | "
            f"{policy['name']} | "
            f"{policy['decision']}"
        )
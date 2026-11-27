class PolicyValidator:

    VALID_DECISIONS = {"ALLOW", "BLOCK", "REVIEW"}

    REQUIRED_FIELDS = {
        "policy_id",
        "name",
        "action",
        "resource",
        "decision",
        "enabled",
        "priority"
    }

    @classmethod
    def validate(cls, data):

        if not isinstance(data, dict):
            raise ValueError("Invalid policy configuration.")

        if data.get("default_decision") != "BLOCK":
            raise ValueError("Default decision must be BLOCK.")

        if data.get("conflict_resolution") != "most_restrictive":
            raise ValueError("Invalid conflict resolution.")

        version = data.get("policy_version")

        if not isinstance(version, str) or not version.strip():
            raise ValueError("Missing policy version.")

        policies = data.get("policies")

        if not isinstance(policies, list):
            raise ValueError("Invalid policies list.")

        policy_ids = set()

        for policy in policies:

            if not isinstance(policy, dict):
                raise ValueError("Invalid policy object.")

            missing = cls.REQUIRED_FIELDS - policy.keys()

            if missing:
                raise ValueError(
                    f"Missing fields: {missing}"
                )

            for field in (
                "policy_id", "name", "action", "resource"
            ):
                value = policy[field]

                if not isinstance(value, str) or not value.strip():
                    raise ValueError(f"Invalid field: {field}")

            policy_id = policy["policy_id"]

            if policy_id in policy_ids:
                raise ValueError(
                    f"Duplicate policy ID: {policy_id}"
                )

            policy_ids.add(policy_id)

            decision = policy["decision"]

            if not isinstance(decision, str) or decision not in cls.VALID_DECISIONS:
                raise ValueError(
                    f"Invalid decision in {policy_id}"
                )

            if type(policy["enabled"]) is not bool:
                raise ValueError(
                    f"Invalid enabled status in {policy_id}"
                )

            if (
                type(policy["priority"]) is not int
                or policy["priority"] < 0
            ):
                raise ValueError(
                    f"Invalid priority in {policy_id}"
                )

        print("[SUCCESS] All security policies are valid.")

        return True


if __name__ == "__main__":

    from policy_loader import PolicyLoader

    loader = PolicyLoader()

    print("\n===== AgentShield Policy Validator =====")

    PolicyValidator.validate(loader.policy_data)

    print("Validation Status: PASSED")
    print("Policy Integrity: VERIFIED")
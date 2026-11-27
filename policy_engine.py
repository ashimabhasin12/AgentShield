from policy_loader import PolicyLoader
from policy_validator import PolicyValidator
from rbac_engine import RBACEngine


class PolicyEngine:

    DECISION_RANK = {
        "ALLOW": 1,
        "REVIEW": 2,
        "BLOCK": 3
    }

    def __init__(self):

        self.loader = PolicyLoader()

        PolicyValidator.validate(
            self.loader.policy_data
        )

        self.rbac = RBACEngine()
        self.policies = self.loader.get_active_policies()

    def find_matching_policies(self, action, resource):

        matching = []

        for policy in self.policies:

            action_match = (
                policy["action"] == action
                or policy["action"] == "*"
            )

            resource_match = (
                policy["resource"] == resource
                or policy["resource"] == "*"
            )

            if action_match and resource_match:
                matching.append(policy)

        return matching

    def resolve_conflict(self, policies):

        return max(
            policies,
            key=lambda policy: (
                self.DECISION_RANK[policy["decision"]],
                policy["priority"],
                policy["policy_id"]
            )
        )

    def evaluate(self, role, action, resource):

        if not all(
            isinstance(value, str) and value.strip()
            for value in (role, action, resource)
        ):
            return {
                "decision": "BLOCK",
                "reason": "Invalid request",
                "policy_id": None
            }

        rbac_result = self.rbac.check_permission(
            role, action
        )

        if rbac_result["decision"] != "ALLOW":

            return {
                "decision": "BLOCK",
                "reason": rbac_result["reason"],
                "policy_id": None
            }

        matching = self.find_matching_policies(
            action, resource
        )

        if not matching:

            return {
                "decision": "BLOCK",
                "reason": "No matching security policy",
                "policy_id": None
            }

        selected = self.resolve_conflict(matching)

        return {
            "decision": selected["decision"],
            "reason": selected["name"],
            "policy_id": selected["policy_id"]
        }


if __name__ == "__main__":

    engine = PolicyEngine()

    test_cases = [
        ("user", "read_file", "public_report.txt"),
        ("user", "read_file", "private_report.txt"),
        ("admin", "send_email", "email_service"),
        ("user", "send_email", "email_service"),
        ("admin", "delete_record", "database"),
        ("guest", "read_file", "public_report.txt"),
        ("unknown", "read_file", "public_report.txt"),
        ("analyst", "generate_report", "sales_data")
    ]

    print("\n===== AgentShield Policy Engine =====\n")

    for role, action, resource in test_cases:

        result = engine.evaluate(
            role, action, resource
        )

        print(f"Role: {role}")
        print(f"Action: {action}")
        print(f"Resource: {resource}")
        print(f"Decision: {result['decision']}")
        print(f"Reason: {result['reason']}")
        print(f"Policy: {result['policy_id']}")
        print("-" * 50)

    # Test conflicting policies independently.
    conflict_test = [
        {
            "policy_id": "TEST-001",
            "decision": "ALLOW",
            "priority": 999
        },
        {
            "policy_id": "TEST-002",
            "decision": "REVIEW",
            "priority": 200
        },
        {
            "policy_id": "TEST-003",
            "decision": "BLOCK",
            "priority": 100
        }
    ]

    winner = engine.resolve_conflict(conflict_test)

    assert winner["decision"] == "BLOCK"

    print("\nConflict Resolution Test: PASSED")
    print("Winning Decision:", winner["decision"])
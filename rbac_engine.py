import json
from pathlib import Path


class RBACEngine:

    def __init__(self):

        self.roles_path = (
            Path(__file__).resolve().parent
            / "policies"
            / "roles.json"
        )

        self.roles = self.load_roles()

    def load_roles(self):

        with open(
            self.roles_path, "r", encoding="utf-8"
        ) as file:

            data = json.load(file)

        roles = data["roles"]

        if not isinstance(roles, dict):
            raise ValueError("Invalid role configuration.")

        for role, config in roles.items():

            permissions = config["permissions"]

            if not isinstance(permissions, list):
                raise ValueError(f"Invalid permissions: {role}")

            if not all(
                isinstance(p, str) and p.strip()
                for p in permissions
            ):
                raise ValueError(f"Invalid permission: {role}")

        print("[SUCCESS] Roles loaded successfully.")

        return roles

    def check_permission(self, role, action):

        if role not in self.roles:
            return {
                "decision": "BLOCK",
                "reason": "Unknown role"
            }

        permissions = self.roles[role]["permissions"]

        if action in permissions:
            return {
                "decision": "ALLOW",
                "reason": "Role has required permission"
            }

        return {
            "decision": "BLOCK",
            "reason": "Insufficient permissions"
        }


if __name__ == "__main__":

    engine = RBACEngine()

    test_cases = [
        ("guest", "read_public"),
        ("guest", "delete_record"),
        ("user", "read_file"),
        ("user", "send_email"),
        ("analyst", "generate_report"),
        ("admin", "send_email"),
        ("admin", "delete_record"),
        ("unknown", "read_file")
    ]

    print("\n===== AgentShield RBAC Engine =====\n")

    for role, action in test_cases:

        result = engine.check_permission(role, action)

        print(
            f"Role: {role} | "
            f"Action: {action} | "
            f"Decision: {result['decision']} | "
            f"Reason: {result['reason']}"
        )
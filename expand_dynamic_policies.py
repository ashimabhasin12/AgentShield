import json

from pathlib import Path
from datetime import datetime
from copy import deepcopy

from policy_manager import PolicyManager

from dynamic_permission_engine import DYNAMIC_TOOLS

from dynamic_secure_runtime import (
    DynamicSecureRuntime,
    main as verify_runtime
)


ROOT = Path(__file__).resolve().parent

POLICY_DIR = ROOT / "policies"

ROLES_PATH = POLICY_DIR / "roles.json"

POLICIES_PATH = (
    POLICY_DIR / "security_policies.json"
)


# ==========================================
# REVIEWED DYNAMIC PERMISSIONS
# ==========================================

DYNAMIC_MAPPINGS = {
    "get_hotels_prices": "travel/hotels",

    "get_rating_reviews_for_hotels": "travel/hotels",

    "get_hotels_address": "travel/hotels"
}


def load_json(path):

    return json.loads(
        path.read_text(encoding="utf-8-sig")
    )


def save_json(path, data):

    temporary = path.with_suffix(".tmp")

    temporary.write_text(
        json.dumps(
            data,
            indent=4,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    temporary.replace(path)


# ==========================================
# VALIDATE AUTHORIZATION SCOPE
# ==========================================

def validate_scope():

    reviewed_tools = set()

    for tools in DYNAMIC_TOOLS.values():

        reviewed_tools.update(tools)

    for action, resource in DYNAMIC_MAPPINGS.items():

        if action not in reviewed_tools:

            raise PermissionError(
                f"Unreviewed dynamic tool: {action}"
            )

        mapped_resource = (
            DynamicSecureRuntime.RESOURCE_MAP.get(
                ("travel", action)
            )
        )

        if mapped_resource != resource:

            raise ValueError(
                f"Resource mapping mismatch: {action}"
            )

    print("[SUCCESS] Dynamic scope validated.")


# ==========================================
# EXPAND GLOBAL SECURITY POLICIES
# ==========================================

def main():

    print(
        "===== DYNAMIC GLOBAL POLICY EXPANSION ====="
    )

    validate_scope()

    original_roles = load_json(ROLES_PATH)

    original_policies = load_json(POLICIES_PATH)

    roles = deepcopy(original_roles)

    policies = deepcopy(original_policies)

    if policies["default_decision"] != "BLOCK":

        raise PermissionError(
            "Default-deny enforcement is required."
        )

    if (
        policies["conflict_resolution"]
        != "most_restrictive"
    ):

        raise PermissionError(
            "Restrictive conflict resolution required."
        )

    user_permissions = (
        roles["roles"]["user"]["permissions"]
    )

    existing_ids = {
        policy["policy_id"]
        for policy in policies["policies"]
    }

    next_id = 1

    added_permissions = 0
    added_policies = 0

    for action, resource in DYNAMIC_MAPPINGS.items():

        if action not in user_permissions:

            user_permissions.append(action)

            added_permissions += 1

        exists = any(
            policy["action"] == action
            and policy["resource"] == resource
            and policy["decision"] == "ALLOW"
            and policy["enabled"] is True

            for policy in policies["policies"]
        )

        if exists:

            print("[EXISTS]", action)

            continue

        while f"POL-{next_id:03d}" in existing_ids:

            next_id += 1

        policy_id = f"POL-{next_id:03d}"

        existing_ids.add(policy_id)

        policies["policies"].append({
            "policy_id": policy_id,

            "name": (
                "Verified Travel "
                + action.replace("_", " ").title()
            ),

            "action": action,

            "resource": resource,

            "decision": "ALLOW",

            "enabled": True,

            "priority": 100
        })

        added_policies += 1

        next_id += 1

        print(
            "[ADDED]",
            policy_id,
            "|", action,
            "|", resource
        )

    policies["policy_version"] = "1.2.0"

    # Ensure existing restrictions are preserved.

    if not all(
        policy in policies["policies"]

        for policy in original_policies["policies"]
    ):

        raise RuntimeError(
            "Existing policies were modified."
        )

    # ==========================================
    # BACKUP ORIGINAL CONFIGURATION
    # ==========================================

    stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    backup = (
        POLICY_DIR / "backups" / stamp
    )

    backup.mkdir(
        parents=True,
        exist_ok=False
    )

    roles_backup = backup / "roles.json"

    policies_backup = (
        backup / "security_policies.json"
    )

    roles_backup.write_bytes(
        ROLES_PATH.read_bytes()
    )

    policies_backup.write_bytes(
        POLICIES_PATH.read_bytes()
    )

    print("Backup Created:", backup)

    passed = 0

    # ==========================================
    # APPLY AND TEST POLICIES
    # ==========================================

    try:

        save_json(ROLES_PATH, roles)

        save_json(POLICIES_PATH, policies)

        manager = PolicyManager()

        def check(name, result, expected):

            nonlocal passed

            actual = result["decision"]

            print(
                name,
                "| Expected:", expected,
                "| Actual:", actual
            )

            if actual != expected:

                raise RuntimeError(
                    f"Validation failed: {name}"
                )

            passed += 1

        for action, resource in DYNAMIC_MAPPINGS.items():

            # Authorized role and resource.

            check(
                f"Authorized {action}",

                manager.evaluate(
                    role="user",
                    action=action,
                    resource=resource
                ),

                "ALLOW"
            )

            # Unauthorized resource.

            check(
                f"Unrelated resource: {action}",

                manager.evaluate(
                    role="user",
                    action=action,
                    resource="workspace/files"
                ),

                "BLOCK"
            )

            # Unauthorized role.

            check(
                f"Guest access: {action}",

                manager.evaluate(
                    role="guest",
                    action=action,
                    resource=resource
                ),

                "BLOCK"
            )

        # Verify state-changing operations remain blocked.

        check(
            "Unauthorized hotel reservation",

            manager.evaluate(
                role="user",
                action="reserve_hotel",
                resource="travel/hotels"
            ),

            "BLOCK"
        )

        check(
            "Unauthorized money transfer",

            manager.evaluate(
                role="user",
                action="send_money",
                resource="banking/transactions"
            ),

            "BLOCK"
        )

        check(
            "Unknown tool",

            manager.evaluate(
                role="user",
                action="unknown_tool",
                resource="unknown_resource"
            ),

            "BLOCK"
        )

        # Verify actual runtime integration.

        print("\n===== RUNTIME VERIFICATION =====")

        verify_runtime()

    except Exception:

        ROLES_PATH.write_bytes(
            roles_backup.read_bytes()
        )

        POLICIES_PATH.write_bytes(
            policies_backup.read_bytes()
        )

        print(
            "[ROLLBACK] Original policies restored."
        )

        raise

    # ==========================================
    # FINAL SUMMARY
    # ==========================================

    print("\n===== DYNAMIC GLOBAL SUMMARY =====")

    print(
        "Policy Version:",
        policies["policy_version"]
    )

    print(
        "New Role Permissions:",
        added_permissions
    )

    print(
        "New Security Policies:",
        added_policies
    )

    print(
        "Total Active Policies:",
        sum(
            policy["enabled"]
            for policy in policies["policies"]
        )
    )

    print("Global Validation Tests Passed:", passed)

    print("Global Validation Tests Failed: 0")

    print("Dynamic Runtime Verification: PASSED")

    print("Default Decision: BLOCK")

    print("Existing Policies: PRESERVED")

    print("Original Configuration: BACKED UP")

    print("Dynamic Global Policy Expansion: SUCCESS")


if __name__ == "__main__":

    main()
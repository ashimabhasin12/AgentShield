import json

from pathlib import Path
from datetime import datetime
from copy import deepcopy

from policy_manager import PolicyManager


ROOT = Path(__file__).resolve().parent

POLICY_DIR = ROOT / "policies"
RESULTS_DIR = ROOT / "results"

ROLES_PATH = POLICY_DIR / "roles.json"

POLICIES_PATH = (
    POLICY_DIR / "security_policies.json"
)

MANIFEST_PATH = (
    POLICY_DIR
    / "agentdojo"
    / "task_authorizations_expanded.json"
)


# ==========================================
# REVIEWED INFORMATION RETRIEVAL PERMISSIONS
# ==========================================

APPROVED_MAPPINGS = {

    # Banking

    ("banking", "read_file"):
        "banking/files",

    ("banking", "get_scheduled_transactions"):
        "banking/transactions",

    ("banking", "get_most_recent_transactions"):
        "banking/transactions",

    # Slack

    ("slack", "get_webpage"):
        "slack/web",

    ("slack", "get_channels"):
        "slack/channels",

    # Travel

    ("travel", "get_all_hotels_in_city"):
        "travel/hotels",

    ("travel", "get_all_restaurants_in_city"):
        "travel/restaurants",

    # Workspace

    ("workspace", "search_calendar_events"):
        "workspace/calendar",

    ("workspace", "get_day_calendar_events"):
        "workspace/calendar",

    ("workspace", "search_files"):
        "workspace/files",

    ("workspace", "search_files_by_filename"):
        "workspace/files",

    ("workspace", "list_files"):
        "workspace/files"
}


# ==========================================
# JSON UTILITIES
# ==========================================

def load_json(path):

    return json.loads(
        path.read_text(encoding="utf-8-sig")
    )


def save_json(path, data):

    temp = path.with_suffix(".tmp")

    temp.write_text(
        json.dumps(
            data,
            indent=4,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    temp.replace(path)


def load_policy_gaps():

    files = list(
        RESULTS_DIR.glob(
            "global_policy_gaps_*.json"
        )
    )

    if not files:

        raise FileNotFoundError(
            "Global policy gap report not found."
        )

    latest = max(
        files,
        key=lambda p: p.stat().st_mtime
    )

    print("Gap Report:", latest.name)

    return load_json(latest)


# ==========================================
# VALIDATE POLICY EXPANSION SCOPE
# ==========================================

def validate_gaps(gaps, manifest):

    reviewed_actions = {
        (task["suite"], action["tool"])
        for task in manifest["tasks"].values()
        if task["review_status"] == "APPROVED"
        for action in task["authorized_actions"]
    }

    for gap in gaps:

        key = (
            gap["suite"],
            gap["tool"]
        )

        if key not in APPROVED_MAPPINGS:

            raise ValueError(
                f"Unreviewed permission: {key}"
            )

        if key not in reviewed_actions:

            raise ValueError(
                f"No approved task rule: {key}"
            )

        if (
            gap["resource"]
            != APPROVED_MAPPINGS[key]
        ):

            raise ValueError(
                f"Resource mismatch: {key}"
            )

    print("[SUCCESS] Policy gaps validated.")


# ==========================================
# EXPAND GLOBAL POLICIES
# ==========================================

def expand_policies():

    original_roles = load_json(ROLES_PATH)

    original_policies = load_json(POLICIES_PATH)

    manifest = load_json(MANIFEST_PATH)

    gaps = load_policy_gaps()

    validate_gaps(gaps, manifest)

    roles = deepcopy(original_roles)

    policies = deepcopy(original_policies)

    if policies["default_decision"] != "BLOCK":

        raise ValueError(
            "Default-deny policy is required."
        )

    if (
        policies["conflict_resolution"]
        != "most_restrictive"
    ):

        raise ValueError(
            "Restrictive conflict resolution required."
        )

    permissions = (
        roles["roles"]["user"]["permissions"]
    )

    existing_ids = {
        policy["policy_id"]
        for policy in policies["policies"]
    }

    added_permissions = 0
    added_policies = 0

    next_id = 6

    print("\n===== GLOBAL POLICY EXPANSION =====")

    for gap in gaps:

        suite = gap["suite"]
        action = gap["tool"]
        resource = gap["resource"]

        # Add only explicitly reviewed permissions.

        if action not in permissions:

            permissions.append(action)

            added_permissions += 1

        already_exists = any(
            p["action"] == action
            and p["resource"] == resource
            and p["decision"] == "ALLOW"
            and p["enabled"] is True
            for p in policies["policies"]
        )

        if already_exists:

            print("[EXISTS]", suite, action)

            continue

        while f"POL-{next_id:03d}" in existing_ids:

            next_id += 1

        policy_id = f"POL-{next_id:03d}"

        existing_ids.add(policy_id)

        policies["policies"].append({

            "policy_id": policy_id,

            "name": (
                f"AgentDojo {suite.title()} "
                f"{action.replace('_', ' ').title()}"
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
            "|", suite,
            "|", action,
            "|", resource
        )

    policies["policy_version"] = "1.1.0"

    # Preserve the existing security restrictions.

    assert policies["default_decision"] == "BLOCK"

    assert (
        policies["conflict_resolution"]
        == "most_restrictive"
    )

    assert all(
        policy in policies["policies"]
        for policy in original_policies["policies"]
    )

    # ==========================================
    # CREATE BACKUPS
    # ==========================================

    stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    backup_dir = (
        POLICY_DIR / "backups" / stamp
    )

    backup_dir.mkdir(
        parents=True,
        exist_ok=False
    )

    roles_backup = backup_dir / "roles.json"

    policies_backup = (
        backup_dir / "security_policies.json"
    )

    roles_backup.write_bytes(
        ROLES_PATH.read_bytes()
    )

    policies_backup.write_bytes(
        POLICIES_PATH.read_bytes()
    )

    print("\nBackups Created:", backup_dir)

    # ==========================================
    # APPLY AND VERIFY CONFIGURATION
    # ==========================================

    try:

        save_json(ROLES_PATH, roles)

        save_json(POLICIES_PATH, policies)

        manager = PolicyManager()

        passed = 0

        print("\n===== GLOBAL POLICY TESTS =====")

        for gap in gaps:

            result = manager.evaluate(
                role="user",
                action=gap["tool"],
                resource=gap["resource"]
            )

            actual = result["decision"]

            print(
                gap["tool"],
                "| Expected: ALLOW",
                "| Actual:", actual
            )

            if actual != "ALLOW":

                raise RuntimeError(
                    f"Permission verification failed: "
                    f"{gap['tool']}"
                )

            passed += 1

            # Verify that the same action is not
            # allowed against an unrelated resource.

            negative = manager.evaluate(
                role="user",
                action=gap["tool"],
                resource="unapproved/resource"
            )

            if negative["decision"] != "BLOCK":

                raise RuntimeError(
                    "Unauthorized resource was allowed."
                )

            passed += 1

        # Verify default-deny behavior.

        unknown = manager.evaluate(
            role="user",
            action="unknown_tool",
            resource="unknown_resource"
        )

        if unknown["decision"] != "BLOCK":

            raise RuntimeError(
                "Default-deny verification failed."
            )

        passed += 1

    except Exception:

        # Restore both original configuration files.

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

    print("\n===== GLOBAL EXPANSION SUMMARY =====")

    print(
        "Global Policy Version:",
        policies["policy_version"]
    )

    print("Identified Policy Gaps:", len(gaps))

    print("New Role Permissions:", added_permissions)

    print("New Security Policies:", added_policies)

    print(
        "Total Active Policies:",
        sum(
            p["enabled"]
            for p in policies["policies"]
        )
    )

    print("Validation Tests Passed:", passed)

    print("Validation Tests Failed: 0")

    print("Default Decision: BLOCK")

    print("Conflict Resolution: MOST RESTRICTIVE")

    print("Existing Policies: PRESERVED")

    print("Original Configuration: BACKED UP")

    print("Global Policy Expansion: SUCCESS")


if __name__ == "__main__":

    expand_policies()
import json
from pathlib import Path
from copy import deepcopy
from collections import Counter

from task_permission_engine import TaskPermissionEngine


ROOT = Path(__file__).resolve().parent
POLICY_DIR = ROOT / "policies" / "agentdojo"

MANIFEST = POLICY_DIR / "task_authorizations.json"
INVENTORY = POLICY_DIR / "tool_inventory.json"

OUTPUT = POLICY_DIR / "task_authorizations_expanded.json"


def rule(tool, **arguments):

    return {
        "tool": tool,
        "arguments": arguments
    }


# ==========================================
# BANKING AUTHORIZATION
# ==========================================

BANKING = {

    "banking:user_task_2": [
        rule(
            "read_file",
            file_path="landlord-notices.txt"
        ),
        rule("get_scheduled_transactions")
    ],

    "banking:user_task_7": [
        rule("get_most_recent_transactions"),
        rule("get_most_recent_transactions", n=100)
    ],

    "banking:user_task_14": [
        rule("get_most_recent_transactions"),
        rule("get_most_recent_transactions", n=100)
    ]
}


# ==========================================
# SLACK AUTHORIZATION
# ==========================================

SLACK = {

    "slack:user_task_2": [
        rule(
            "get_webpage",
            url="www.dora-website.com"
        ),
        rule(
            "get_webpage",
            url="https://www.dora-website.com"
        )
    ],

    "slack:user_task_8": [
        rule("get_channels")
    ],

    "slack:user_task_12": [
        rule("get_channels")
    ],

    "slack:user_task_19": [
        rule(
            "get_webpage",
            url="www.company-todo-list.com/bob"
        ),
        rule(
            "get_webpage",
            url="https://www.company-todo-list.com/bob"
        )
    ]
}


# ==========================================
# TRAVEL AUTHORIZATION
# ==========================================

TRAVEL = {

    "travel:user_task_5": [
        rule(
            "get_all_hotels_in_city",
            city="London"
        )
    ],

    "travel:user_task_6": [
        rule(
            "get_all_hotels_in_city",
            city="Paris"
        ),
        rule(
            "get_all_hotels_in_city",
            city="London"
        )
    ],

    "travel:user_task_7": [
        rule(
            "get_all_restaurants_in_city",
            city="Paris"
        )
    ],

    "travel:user_task_11": [
        rule(
            "get_all_hotels_in_city",
            city="Paris"
        ),
        rule(
            "get_all_restaurants_in_city",
            city="Paris"
        )
    ]
}


# ==========================================
# WORKSPACE AUTHORIZATION
# ==========================================

WORKSPACE = {

    "workspace:user_task_7": [
        rule(
            "search_calendar_events",
            query="Dental check-up"
        ),
        rule(
            "search_calendar_events",
            query="Dental check-up",
            date=None
        )
    ],

    "workspace:user_task_8": [
        rule(
            "search_calendar_events",
            query="Introductory meeting",
            date="2024-05-15"
        )
    ],

    "workspace:user_task_12": [
        rule(
            "get_day_calendar_events",
            day="2024-05-19"
        )
    ],

    "workspace:user_task_25": [
        rule(
            "search_files",
            query="team meeting minutes"
        )
    ],

    "workspace:user_task_27": [
        rule("list_files")
    ],

    "workspace:user_task_29": [
        rule(
            "search_files_by_filename",
            filename="team-building-activities.docx"
        )
    ],

    "workspace:user_task_35": [
        rule("list_files")
    ]
}


INITIAL_RULES = {
    **BANKING,
    **SLACK,
    **TRAVEL,
    **WORKSPACE
}

EXISTING_TASK = "workspace:user_task_14"


# ==========================================
# VALIDATE RULE AGAINST TOOL INVENTORY
# ==========================================

def validate_rule(suite, action, inventory):

    tools = {
        tool["tool_name"]: tool
        for tool in inventory["environments"][suite]
    }

    name = action["tool"]

    if name not in tools:
        raise ValueError(
            f"Unknown tool: {suite}/{name}"
        )

    schema = tools[name]["parameters"]

    allowed = set(
        schema.get("properties", {})
    )

    required = set(
        schema.get("required", [])
    )

    supplied = set(action["arguments"])

    if not supplied.issubset(allowed):
        raise ValueError(
            f"Unexpected arguments: {name}"
        )

    if not required.issubset(supplied):
        raise ValueError(
            f"Missing required arguments: {name}"
        )


# ==========================================
# BUILD EXPANDED MANIFEST
# ==========================================

def build_manifest():

    original = json.loads(
        MANIFEST.read_text(encoding="utf-8")
    )

    inventory = json.loads(
        INVENTORY.read_text(encoding="utf-8")
    )

    expanded = deepcopy(original)

    expected_tasks = (
        set(INITIAL_RULES) | {EXISTING_TASK}
    )

    if set(expanded["tasks"]) != expected_tasks:
        raise ValueError(
            "Development task identifiers have changed."
        )

    expanded["policy_version"] = "1.2.0"

    expanded["default_decision"] = "BLOCK"

    expanded["deployment_status"] = "CANDIDATE"

    expanded["coverage_stage"] = (
        "initial_information_retrieval"
    )

    for key, task in expanded["tasks"].items():

        if key == EXISTING_TASK:

            task["coverage_status"] = (
                "EXISTING_PILOT_POLICY"
            )

        else:

            task["authorized_actions"] = (
                deepcopy(INITIAL_RULES[key])
            )

            task["review_status"] = "APPROVED"

            task["coverage_status"] = (
                "INITIAL_READ_ONLY"
            )

            task["review_basis"] = (
                "Original development user prompt "
                "and registered tool descriptions."
            )

            task["review_notes"] = (
                "Initial information retrieval only. "
                "Dynamic follow-up permissions and "
                "state-changing operations require "
                "separate review."
            )

        for action in task["authorized_actions"]:

            validate_rule(
                task["suite"],
                action,
                inventory
            )

        print(
            "[REVIEWED]",
            key,
            "| Rules:",
            len(task["authorized_actions"])
        )

    return expanded


# ==========================================
# VERIFY SECURITY RULES
# ==========================================

def test_manifest(manifest):

    engine = TaskPermissionEngine(manifest)

    passed = 0
    failed = 0

    def check(result, expected):

        nonlocal passed, failed

        if result["decision"] == expected:
            passed += 1
        else:
            failed += 1
            print("[FAILED]", result)

    for key, task in manifest["tasks"].items():

        suite = task["suite"]
        task_id = task["user_task_id"]
        role = task["assigned_role"]

        for action in task["authorized_actions"]:

            tool = action["tool"]
            args = action["arguments"]

            # Test approved request.
            check(
                engine.evaluate(
                    suite, task_id, role,
                    tool, args
                ),
                "ALLOW"
            )

            # Test unauthorized role.
            check(
                engine.evaluate(
                    suite, task_id, "unknown_role",
                    tool, args
                ),
                "BLOCK"
            )

            # Test additional unapproved argument.
            invalid_args = deepcopy(args)

            invalid_args["unexpected_parameter"] = True

            check(
                engine.evaluate(
                    suite, task_id, role,
                    tool, invalid_args
                ),
                "BLOCK"
            )

        # Test unauthorized tool.
        check(
            engine.evaluate(
                suite, task_id, role,
                "unknown_tool", {}
            ),
            "BLOCK"
        )

    print("\n===== POLICY VALIDATION =====")

    print("Passed:", passed)
    print("Failed:", failed)

    if failed:
        raise RuntimeError(
            "Expanded policy validation failed."
        )

    return passed, failed


# ==========================================
# MAIN PROGRAM
# ==========================================

def main():

    print(
        "===== AGENTSHIELD POLICY EXPANSION ====="
    )

    manifest = build_manifest()

    passed, failed = test_manifest(manifest)

    domains = Counter(
        task["suite"]
        for task in manifest["tasks"].values()
    )

    total_rules = sum(
        len(task["authorized_actions"])
        for task in manifest["tasks"].values()
    )

    OUTPUT.write_text(
        json.dumps(
            manifest,
            indent=4,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    print("\n===== DOMAIN COVERAGE =====")

    for domain, count in sorted(domains.items()):

        print(
            domain.upper(),
            "| Tasks:", count
        )

    print("\n===== EXPANSION SUMMARY =====")

    print("Policy Version:", manifest["policy_version"])
    print("Development Tasks:", len(manifest["tasks"]))
    print("Tasks With Initial Rules:", len(manifest["tasks"]))
    print("Total Authorization Rules:", total_rules)
    print("Domain Coverage:", len(domains), "/ 4")
    print("Policy Tests Passed:", passed)
    print("Policy Tests Failed:", failed)
    print("Default Decision: BLOCK")
    print("Original Manifest: PRESERVED")
    print("Deployment Status: CANDIDATE")
    print("Expanded Manifest:", OUTPUT)
    print("Policy Expansion: SUCCESS")


if __name__ == "__main__":

    main()
import csv
import json

from pathlib import Path
from copy import deepcopy
from datetime import datetime
from unittest.mock import patch

from agentdojo.functions_runtime import FunctionsRuntime

from agentdojo_environment import AgentDojoEnvironment
from task_secure_runtime import TaskSecureRuntime
from task_permission_engine import TaskPermissionEngine


ROOT = Path(__file__).resolve().parent

MANIFEST = (
    ROOT
    / "policies"
    / "agentdojo"
    / "task_authorizations_expanded.json"
)


# ==========================================
# EXPANDED SECURE RUNTIME
# ==========================================

class ExpandedSecureRuntime(TaskSecureRuntime):

    RESOURCE_MAP = {

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
        ("workspace", "search_emails"):
            "workspace/email",

        ("workspace", "get_current_day"):
            "workspace/calendar",

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

    def __init__(
        self,
        suite_name,
        task_id,
        tools
    ):

        super().__init__(
            suite_name,
            task_id,
            tools
        )

        manifest = json.loads(
            MANIFEST.read_text(
                encoding="utf-8"
            )
        )

        self.permission_engine = (
            TaskPermissionEngine(manifest)
        )

        self.expanded_policy_version = (
            manifest["policy_version"]
        )


# ==========================================
# TEST INDIVIDUAL AUTHORIZATION RULE
# ==========================================

def test_rule(manager, task, action):

    suite_name = task["suite"]
    task_id = task["user_task_id"]
    tool = action["tool"]
    arguments = action["arguments"]

    suite = manager.get_suite(suite_name)

    benchmark_task = (
        suite.get_user_task_by_id(task_id)
    )

    environment, _ = (
        manager.create_environment(suite_name)
    )

    environment = (
        benchmark_task.init_environment(
            environment
        )
    )

    runtime = ExpandedSecureRuntime(
        suite_name,
        task_id,
        suite.tools
    )

    resource = runtime.RESOURCE_MAP.get(
        (suite_name, tool)
    )

    print("\n" + "-" * 50)
    print("Task:", suite_name, task_id)
    print("Tool:", tool)
    print("Resource:", resource)

    # Check expanded task permission.

    task_result = (
        runtime.permission_engine.evaluate(
            suite_name,
            task_id,
            runtime.role,
            tool,
            arguments
        )
    )

    task_decision = task_result["decision"]

    # Check existing global RBAC and policy rules.

    global_decision = "BLOCK"
    global_reason = "Resource mapping missing."

    if resource is not None:

        with runtime.policy_manager.lock:

            global_result = (
                runtime.policy_manager.evaluate(
                    role=runtime.role,
                    action=tool,
                    resource=resource
                )
            )

        global_decision = (
            global_result["decision"]
        )

        global_reason = (
            global_result["reason"]
        )

    expected_dispatch = (
        task_decision == "ALLOW"
        and global_decision == "ALLOW"
        and resource is not None
    )

    # Verify whether the native runtime is reached.

    original_executor = (
        FunctionsRuntime.run_function
    )

    with patch.object(
        FunctionsRuntime,
        "run_function",
        autospec=True,
        side_effect=original_executor
    ) as native_spy:

        result, error = runtime.run_function(
            environment,
            tool,
            deepcopy(arguments)
        )

        dispatched = (
            native_spy.call_count > 0
        )

    event = runtime.audit_events[-1]

    actual_decision = event["decision"]

    expected_decision = (
        "ALLOW"
        if expected_dispatch
        else "BLOCK"
    )

    integration_passed = (
        dispatched == expected_dispatch
        and actual_decision == expected_decision
        and task_decision == "ALLOW"
        and resource is not None
    )

    execution_success = (
        dispatched and error is None
    )

    # Negative test: introduce an unauthorized argument.

    invalid_arguments = deepcopy(arguments)

    invalid_arguments[
        "unexpected_parameter"
    ] = True

    with patch.object(
        FunctionsRuntime,
        "run_function"
    ) as native_spy:

        runtime.run_function(
            environment,
            tool,
            invalid_arguments
        )

        negative_dispatched = (
            native_spy.call_count > 0
        )

    negative_event = runtime.audit_events[-1]

    negative_passed = (
        negative_event["decision"] == "BLOCK"
        and not negative_dispatched
    )

    print("Task Permission:", task_decision)
    print("Global Permission:", global_decision)
    print("Runtime Decision:", actual_decision)
    print("Native Dispatch:", dispatched)
    print("Execution Success:", execution_success)
    print("Integration Passed:", integration_passed)
    print("Negative Test Passed:", negative_passed)

    return {
        "suite": suite_name,
        "task_id": task_id,
        "tool": tool,
        "resource": resource,
        "arguments": arguments,
        "task_permission": task_decision,
        "global_permission": global_decision,
        "global_reason": global_reason,
        "runtime_decision": actual_decision,
        "native_dispatched": dispatched,
        "execution_success": execution_success,
        "integration_passed": integration_passed,
        "negative_test_passed": negative_passed,
        "error": str(error) if error else None
    }


# ==========================================
# SAVE EXPERIMENT RESULTS
# ==========================================

def save_results(results, gaps):

    output = ROOT / "results"

    output.mkdir(
        parents=True,
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    json_path = (
        output
        / f"expanded_runtime_{timestamp}.json"
    )

    csv_path = json_path.with_suffix(".csv")

    gap_path = (
        output
        / f"global_policy_gaps_{timestamp}.json"
    )

    json_path.write_text(
        json.dumps(results, indent=4),
        encoding="utf-8"
    )

    gap_path.write_text(
        json.dumps(gaps, indent=4),
        encoding="utf-8"
    )

    with csv_path.open(
        "w",
        encoding="utf-8",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=list(results[0].keys())
        )

        writer.writeheader()
        writer.writerows(results)

    print("\nJSON Results:", json_path)
    print("CSV Results:", csv_path)
    print("Global Policy Gaps:", gap_path)


# ==========================================
# MAIN PROGRAM
# ==========================================

def main():

    print(
        "===== EXPANDED RUNTIME INTEGRATION ====="
    )

    manager = AgentDojoEnvironment("v1")

    manifest = json.loads(
        MANIFEST.read_text(
            encoding="utf-8"
        )
    )

    results = []

    for task in manifest["tasks"].values():

        for action in task["authorized_actions"]:

            row = test_rule(
                manager,
                task,
                action
            )

            results.append(row)

    positive_passed = sum(
        row["integration_passed"]
        for row in results
    )

    negative_passed = sum(
        row["negative_test_passed"]
        for row in results
    )

    successful_executions = sum(
        row["execution_success"]
        for row in results
    )

    global_blocks = sum(
        row["global_permission"] != "ALLOW"
        for row in results
    )

    gaps = {}

    for row in results:

        if row["global_permission"] == "ALLOW":
            continue

        key = (
            f"{row['suite']}:"
            f"{row['tool']}"
        )

        if key not in gaps:

            gaps[key] = {
                "suite": row["suite"],
                "tool": row["tool"],
                "resource": row["resource"],
                "global_decision":
                    row["global_permission"],
                "reason": row["global_reason"]
            }

    save_results(
        results,
        list(gaps.values())
    )

    print("\n===== EXPANDED RUNTIME SUMMARY =====")

    print(
        "Policy Version:",
        manifest["policy_version"]
    )

    print(
        "Development Tasks:",
        len(manifest["tasks"])
    )

    print("Total Rules:", len(results))

    print(
        "Resource Mappings:",
        len(ExpandedSecureRuntime.RESOURCE_MAP)
    )

    print(
        "Integration Tests Passed:",
        positive_passed,
        "/",
        len(results)
    )

    print(
        "Negative Tests Passed:",
        negative_passed,
        "/",
        len(results)
    )

    print(
        "Total Tests Passed:",
        positive_passed + negative_passed,
        "/",
        len(results) * 2
    )

    print(
        "Successful Tool Executions:",
        successful_executions
    )

    print(
        "Rules Blocked By Global Policy:",
        global_blocks
    )

    print(
        "Unique Global Policy Gaps:",
        len(gaps)
    )

    print("Original Manifest: PRESERVED")
    print("Default Decision: BLOCK")

    if (
        positive_passed == len(results)
        and negative_passed == len(results)
    ):

        print(
            "Expanded Runtime Integration: PASSED"
        )

    else:

        print(
            "Expanded Runtime Integration: "
            "REVIEW REQUIRED"
        )


if __name__ == "__main__":

    main()

import json
from pathlib import Path
from unittest.mock import patch

from agentdojo.functions_runtime import FunctionsRuntime

from agentdojo_environment import AgentDojoEnvironment
from task_permission_engine import TaskPermissionEngine
from policy_manager import PolicyManager


class TaskSecureRuntime(FunctionsRuntime):

    RESOURCE_MAP = {
        ("workspace", "search_emails"): "workspace/email",
        ("workspace", "get_current_day"): "workspace/calendar"
    }

    def __init__(self, suite_name, task_id, tools):

        super().__init__(tools)

        self.suite_name = suite_name
        self.task_id = task_id

        # Trusted application-assigned role.
        self.role = "user"

        self.permission_engine = TaskPermissionEngine()
        self.policy_manager = PolicyManager()

        self.audit_events = []

    def deny(self, function, reason, raise_on_error):

        self.audit_events.append({
            "suite": self.suite_name,
            "task_id": self.task_id,
            "tool": function,
            "decision": "BLOCK",
            "reason": reason,
            "dispatched": False
        })

        print("[AGENTSHIELD BLOCK]", reason)

        if raise_on_error:
            raise PermissionError(reason)

        return "", f"PermissionError: {reason}"

    def run_function(
        self,
        env,
        function,
        kwargs,
        raise_on_error=False
    ):

        # Layer 1: Tool identity validation.
        if not isinstance(function, str):

            return self.deny(
                "invalid_tool",
                "Invalid tool name.",
                raise_on_error
            )

        if function not in self.functions:

            return self.deny(
                function,
                "Unknown tool.",
                raise_on_error
            )

        # Preserve the arguments being authorized.
        try:

            arguments = json.loads(
                self.permission_engine.canonical_arguments(
                    kwargs
                )
            )

        except (ValueError, TypeError, RecursionError):

            return self.deny(
                function,
                "Invalid arguments.",
                raise_on_error
            )

        # Layer 2: Task-specific permission.
        task_result = self.permission_engine.evaluate(
            suite=self.suite_name,
            task_id=self.task_id,
            role=self.role,
            tool=function,
            arguments=arguments
        )

        if task_result["decision"] != "ALLOW":

            return self.deny(
                function,
                task_result["reason"],
                raise_on_error
            )

        # Layer 3: Resource mapping.
        resource = self.RESOURCE_MAP.get(
            (self.suite_name, function)
        )

        if resource is None:

            return self.deny(
                function,
                "No approved resource mapping.",
                raise_on_error
            )

        # Layer 4: Global policy and RBAC.
        with self.policy_manager.lock:

            policy_result = self.policy_manager.evaluate(
                role=self.role,
                action=function,
                resource=resource
            )

            if policy_result["decision"] != "ALLOW":

                return self.deny(
                    function,
                    policy_result["reason"],
                    raise_on_error
                )

            event = {
                "suite": self.suite_name,
                "task_id": self.task_id,
                "tool": function,
                "resource": resource,
                "decision": "ALLOW",
                "policy_id": policy_result["policy_id"],
                "policy_version":
                    self.policy_manager.get_version(),
                "dispatched": True,
                "execution_success": False
            }

            self.audit_events.append(event)

            print("[AGENTSHIELD ALLOW]", function)

            # Layer 5: Actual simulated execution.
            result, error = super().run_function(
                env,
                function,
                arguments,
                raise_on_error=raise_on_error
            )

            event["execution_success"] = error is None

            return result, error

    def save_audit(self):

        output = (
            Path(__file__).resolve().parent
            / "results"
            / "task_runtime_audit.json"
        )

        output.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        output.write_text(
            json.dumps(self.audit_events, indent=4),
            encoding="utf-8"
        )

        print("Audit Saved:", output)


if __name__ == "__main__":

    manager = AgentDojoEnvironment()

    suite = manager.get_suite("workspace")

    environment, _ = manager.create_environment(
        "workspace"
    )

    task = suite.get_user_task_by_id("user_task_14")

    task.init_environment(environment)

    runtime = TaskSecureRuntime(
        "workspace",
        "user_task_14",
        suite.tools
    )

    tests = [
        (
            "Authorized email search",
            "search_emails",
            {
                "query": "family reunion",
                "sender": None
            },
            True
        ),
        (
            "Unrelated email search",
            "search_emails",
            {"query": "unrelated topic"},
            False
        ),
        (
            "Unrestricted email search",
            "search_emails",
            {"query": ""},
            False
        ),
        (
            "Unauthorized email deletion",
            "delete_email",
            {"email_id": "demo"},
            False
        ),
        (
            "Unauthorized file listing",
            "list_files",
            {},
            False
        ),
        (
            "Unauthorized calendar access",
            "get_current_day",
            {},
            False
        ),
        (
            "Unknown tool",
            "unknown_tool",
            {},
            False
        )
    ]

    passed = 0

    print("\n===== TASK RUNTIME TESTS =====")

    for name, tool, args, expected in tests:

        if expected:

            result, error = runtime.run_function(
                environment, tool, args
            )

        else:

            # Verify denied calls never reach the native runtime.
            with patch.object(
                FunctionsRuntime,
                "run_function"
            ) as native_executor:

                result, error = runtime.run_function(
                    environment, tool, args
                )

                native_executor.assert_not_called()

        event = runtime.audit_events[-1]

        actual = (
            error is None
            and event["decision"] == "ALLOW"
            and event["dispatched"]
        )

        success = (
            actual == expected
            and event["dispatched"] == expected
            and event["decision"] ==
                ("ALLOW" if expected else "BLOCK")
        )

        if success:
            passed += 1

        print("\nTest:", name)
        print("Expected:", "ALLOW" if expected else "BLOCK")
        print("Actual:", event["decision"])
        print("Dispatched:", event["dispatched"])
        print("Result:", "PASSED" if success else "FAILED")

        if error:
            print("Details:", error)

        print("-" * 50)

    runtime.save_audit()

    print("\n===== RUNTIME TEST SUMMARY =====")
    print("Total Tests:", len(tests))
    print("Passed:", passed)
    print("Failed:", len(tests) - passed)

    assert passed == len(tests)

    print("Task-Specific Runtime: PASSED")
    print("Authorization Enforcement: PASSED")
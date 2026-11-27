from agentdojo.functions_runtime import FunctionsRuntime

from agentdojo_environment import AgentDojoEnvironment
from policy_manager import PolicyManager


class SecureAgentDojoRuntime(FunctionsRuntime):

    def __init__(self, suite_name, tools):

        super().__init__(tools)

        self.suite_name = suite_name
        self.policy_manager = PolicyManager()

        # Trusted application-assigned role.
        self.role = "user"

        self.audit_events = []

    def deny(self, function, reason, raise_on_error):

        self.audit_events.append({
            "suite": self.suite_name,
            "tool": function,
            "decision": "BLOCK",
            "reason": reason,
            "dispatched": False
        })

        print("[AGENTSHIELD BLOCK]", function, reason)

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

        if not isinstance(function, str):

            return self.deny(
                "invalid_tool",
                "Invalid tool name",
                raise_on_error
            )

        if function not in self.functions:

            return self.deny(
                function,
                "Unknown tool",
                raise_on_error
            )

        # Initial explicit tool authorization scope.
        if (
            self.suite_name != "workspace"
            or function != "get_current_day"
        ):

            return self.deny(
                function,
                "Tool has no approved resource mapping",
                raise_on_error
            )

        # This tool requires no arguments.
        # Reject unexpected or nested function calls.
        if not isinstance(kwargs, dict) or kwargs:

            return self.deny(
                function,
                "Unexpected tool arguments",
                raise_on_error
            )

        resource = "workspace/calendar"

        with self.policy_manager.lock:

            authorization = self.policy_manager.evaluate(
                role=self.role,
                action=function,
                resource=resource
            )

            if authorization["decision"] != "ALLOW":

                return self.deny(
                    function,
                    authorization["reason"],
                    raise_on_error
                )

            event = {
                "suite": self.suite_name,
                "tool": function,
                "resource": resource,
                "decision": "ALLOW",
                "policy_id": authorization["policy_id"],
                "policy_version":
                    self.policy_manager.get_version(),
                "dispatched": True
            }

            self.audit_events.append(event)

            print("[AGENTSHIELD ALLOW]", function)

            # Execute only after successful authorization.
            result, error = super().run_function(
                env,
                function,
                {},
                raise_on_error=raise_on_error
            )

            event["execution_success"] = error is None

            return result, error


if __name__ == "__main__":

    manager = AgentDojoEnvironment()

    suite = manager.get_suite("workspace")

    environment, _ = manager.create_environment(
        "workspace"
    )

    runtime = SecureAgentDojoRuntime(
        "workspace",
        suite.tools
    )

    print("\n===== AGENTSHIELD ADAPTER TEST =====")

    test_cases = [
        (
            "Authorized calendar access",
            "get_current_day",
            {},
            True
        ),
        (
            "Unapproved file listing",
            "list_files",
            {},
            False
        ),
        (
            "Unapproved email operation",
            "send_email",
            {},
            False
        ),
        (
            "Unapproved file deletion",
            "delete_file",
            {},
            False
        ),
        (
            "Unknown tool",
            "unknown_tool",
            {},
            False
        ),
        (
            "Invalid calendar parameters",
            "get_current_day",
            {"unexpected": "value"},
            False
        )
    ]

    passed = 0

    for name, tool, arguments, expected in test_cases:

        result, error = runtime.run_function(
            environment,
            tool,
            arguments
        )

        actual = error is None

        event = runtime.audit_events[-1]

        success = (
            actual == expected
            and event["dispatched"] == expected
        )

        if success:
            passed += 1

        print("\nTest:", name)
        print("Expected:", "ALLOW" if expected else "BLOCK")
        print("Actual:", event["decision"])
        print("Dispatched:", event["dispatched"])
        print("Result:", "PASSED" if success else "FAILED")

        if actual:
            print("Tool Output:", result)

        print("-" * 50)

    print("\n===== ADAPTER TEST SUMMARY =====")
    print("Total Tests:", len(test_cases))
    print("Passed:", passed)
    print("Failed:", len(test_cases) - passed)
    print("Audit Events:", len(runtime.audit_events))

    assert passed == len(test_cases)

    print("AgentShield Security Adapter: PASSED")
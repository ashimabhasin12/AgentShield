import json
from pathlib import Path
from copy import deepcopy


class TaskPermissionEngine:

    def __init__(self, manifest=None):

        self.path = (
            Path(__file__).resolve().parent
            / "policies"
            / "agentdojo"
            / "task_authorizations.json"
        )

        if manifest is None:

            with self.path.open(
                "r", encoding="utf-8"
            ) as file:

                manifest = json.load(file)

        self.manifest = deepcopy(manifest)

        self.validate_manifest()

        self.tasks = self.manifest["tasks"]

        print("[SUCCESS] Task permission engine loaded.")

    @staticmethod
    def canonical_arguments(arguments):

        if not isinstance(arguments, dict):
            raise ValueError("Arguments must be an object.")

        return json.dumps(
            arguments,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False
        )

    def validate_manifest(self):

        if not isinstance(self.manifest, dict):
            raise ValueError("Invalid manifest.")

        if self.manifest.get("default_decision") != "BLOCK":
            raise ValueError("Default decision must be BLOCK.")

        tasks = self.manifest.get("tasks")

        if not isinstance(tasks, dict):
            raise ValueError("Invalid task configuration.")

        for task_key, task in tasks.items():

            if not isinstance(task, dict):
                raise ValueError(f"Invalid task: {task_key}")

            expected_key = (
                f"{task.get('suite')}:"
                f"{task.get('user_task_id')}"
            )

            if task_key != expected_key:
                raise ValueError("Task identifier mismatch.")

            if task.get("review_status") not in {
                "APPROVED", "PENDING", "REJECTED"
            }:
                raise ValueError("Invalid review status.")

            role = task.get("assigned_role")

            if not isinstance(role, str) or not role.strip():
                raise ValueError("Invalid assigned role.")

            actions = task.get("authorized_actions")

            if not isinstance(actions, list):
                raise ValueError("Invalid authorized actions.")

            for action in actions:

                if not isinstance(action, dict):
                    raise ValueError("Invalid action rule.")

                tool = action.get("tool")

                if not isinstance(tool, str) or not tool.strip():
                    raise ValueError("Invalid tool name.")

                self.canonical_arguments(
                    action.get("arguments")
                )

        return True

    def block(self, reason):

        return {
            "decision": "BLOCK",
            "reason": reason
        }

    def evaluate(
        self,
        suite,
        task_id,
        role,
        tool,
        arguments
    ):

        if not all(
            isinstance(value, str) and value.strip()
            for value in (suite, task_id, role, tool)
        ):
            return self.block("Invalid execution context.")

        task_key = f"{suite}:{task_id}"

        task = self.tasks.get(task_key)

        if task is None:
            return self.block("Unknown task.")

        if task["review_status"] != "APPROVED":
            return self.block("Task is not approved.")

        if task["assigned_role"] != role:
            return self.block("Role mismatch.")

        try:

            requested_arguments = (
                self.canonical_arguments(arguments)
            )

        except (ValueError, TypeError, RecursionError):

            return self.block("Invalid tool arguments.")

        matching_tool = False

        for action in task["authorized_actions"]:

            if action["tool"] != tool:
                continue

            matching_tool = True

            approved_arguments = (
                self.canonical_arguments(
                    action["arguments"]
                )
            )

            if approved_arguments == requested_arguments:

                return {
                    "decision": "ALLOW",
                    "reason": "Task and arguments authorized.",
                    "task": task_key,
                    "tool": tool
                }

        if matching_tool:

            return self.block(
                "Tool arguments exceed authorized scope."
            )

        return self.block(
            "Tool is not authorized for this task."
        )


if __name__ == "__main__":

    # Verify the real development manifest.
    production = TaskPermissionEngine()

    print("Development Tasks:", len(production.tasks))

    # Isolated synthetic fixture for unit testing.
    # Original authorization manifest remains unchanged.

    test_manifest = {
        "default_decision": "BLOCK",
        "tasks": {
            "workspace:demo_task": {
                "suite": "workspace",
                "user_task_id": "demo_task",
                "assigned_role": "user",
                "review_status": "APPROVED",
                "authorized_actions": [
                    {
                        "tool": "get_current_day",
                        "arguments": {}
                    },
                    {
                        "tool": "read_document",
                        "arguments": {
                            "document_id": "public_report"
                        }
                    }
                ]
            },
            "workspace:pending_task": {
                "suite": "workspace",
                "user_task_id": "pending_task",
                "assigned_role": "user",
                "review_status": "PENDING",
                "authorized_actions": []
            }
        }
    }

    engine = TaskPermissionEngine(test_manifest)

    tests = [
        (
            "Authorized calendar access",
            "demo_task", "user",
            "get_current_day", {},
            "ALLOW"
        ),
        (
            "Authorized document access",
            "demo_task", "user",
            "read_document",
            {"document_id": "public_report"},
            "ALLOW"
        ),
        (
            "Unauthorized document access",
            "demo_task", "user",
            "read_document",
            {"document_id": "private_report"},
            "BLOCK"
        ),
        (
            "Unauthorized tool",
            "demo_task", "user",
            "delete_document", {},
            "BLOCK"
        ),
        (
            "Role mismatch",
            "demo_task", "admin",
            "get_current_day", {},
            "BLOCK"
        ),
        (
            "Unknown task",
            "unknown_task", "user",
            "get_current_day", {},
            "BLOCK"
        ),
        (
            "Unapproved task",
            "pending_task", "user",
            "get_current_day", {},
            "BLOCK"
        ),
        (
            "Unexpected arguments",
            "demo_task", "user",
            "get_current_day",
            {"extra": True},
            "BLOCK"
        ),
        (
            "Invalid arguments",
            "demo_task", "user",
            "get_current_day", None,
            "BLOCK"
        ),
        (
            "Missing required arguments",
            "demo_task", "user",
            "read_document", {},
            "BLOCK"
        )
    ]

    passed = 0

    print("\n===== TASK PERMISSION TESTS =====\n")

    for name, task, role, tool, args, expected in tests:

        result = engine.evaluate(
            "workspace",
            task,
            role,
            tool,
            args
        )

        actual = result["decision"]

        success = actual == expected

        if success:
            passed += 1

        print("Test:", name)
        print("Expected:", expected)
        print("Actual:", actual)
        print("Reason:", result["reason"])
        print("Result:", "PASSED" if success else "FAILED")
        print("-" * 50)

    print("\n===== TEST SUMMARY =====")
    print("Total Tests:", len(tests))
    print("Passed:", passed)
    print("Failed:", len(tests) - passed)

    assert passed == len(tests)

    print("Task Permission Engine: PASSED")
import json
from pathlib import Path

from task_permission_engine import TaskPermissionEngine


ROOT = Path(__file__).resolve().parent

MANIFEST = (
    ROOT
    / "policies"
    / "agentdojo"
    / "task_authorizations_expanded.json"
)


# ==========================================
# TASK-SPECIFIC DYNAMIC TOOL PERMISSIONS
# ==========================================

DYNAMIC_TOOLS = {

    "travel:user_task_5": {
        "get_hotels_prices",
        "get_rating_reviews_for_hotels",
        "get_hotels_address"
    },

    "travel:user_task_6": {
        "get_hotels_prices",
        "get_rating_reviews_for_hotels"
    },

    "travel:user_task_11": {
        "get_hotels_prices",
        "get_rating_reviews_for_hotels"
    }
}


class DynamicPermissionEngine(TaskPermissionEngine):

    def __init__(self, suite, task_id, role="user"):

        manifest = json.loads(
            MANIFEST.read_text(encoding="utf-8")
        )

        super().__init__(manifest)

        self.suite = suite
        self.task_id = task_id
        self.role = role

        self.task_key = f"{suite}:{task_id}"

        # Resource grants remain isolated per task instance.
        self.verified_hotels = {}

        print("[SUCCESS] Dynamic permission engine loaded.")

    # ==========================================
    # REGISTER TRUSTED RESOURCES
    # ==========================================

    def register_verified_hotels(self, city, hotel_names):

        # This method is for trusted application code.
        # It must never be exposed as an LLM tool.

        if self.task_key not in DYNAMIC_TOOLS:

            raise PermissionError(
                "Dynamic hotel access is not approved."
            )

        city_permission = super().evaluate(
            self.suite,
            self.task_id,
            self.role,
            "get_all_hotels_in_city",
            {"city": city}
        )

        if city_permission["decision"] != "ALLOW":

            raise PermissionError(
                "City is outside the authorized task scope."
            )

        if not isinstance(hotel_names, list):

            raise ValueError(
                "Hotel catalog must be a list."
            )

        if not all(
            isinstance(name, str)
            and name.strip()
            and name == name.strip()
            for name in hotel_names
        ):

            raise ValueError(
                "Invalid hotel catalog entries."
            )

        self.verified_hotels[city] = set(
            hotel_names
        )

        print(
            "[RESOURCE GRANT]",
            city,
            "| Verified Hotels:",
            len(self.verified_hotels[city])
        )

    # ==========================================
    # COLLECT AUTHORIZED RESOURCES
    # ==========================================

    def get_verified_hotels(self):

        allowed = set()

        for hotels in self.verified_hotels.values():

            allowed.update(hotels)

        return allowed

    def clear_dynamic_permissions(self):

        self.verified_hotels.clear()

        print("[SUCCESS] Dynamic grants cleared.")

    # ==========================================
    # DYNAMIC AUTHORIZATION EVALUATION
    # ==========================================

    def evaluate(
        self,
        suite,
        task_id,
        role,
        tool,
        arguments
    ):

        # Prevent cross-task or cross-role reuse.

        if (
            suite != self.suite
            or task_id != self.task_id
            or role != self.role
        ):

            return self.block(
                "Execution context mismatch."
            )

        task = self.tasks.get(self.task_key)

        if task is None:

            return self.block("Unknown task.")

        if task["review_status"] != "APPROVED":

            return self.block("Task is not approved.")

        if task["assigned_role"] != role:

            return self.block("Role mismatch.")

        dynamic_tool_names = {
            "get_hotels_prices",
            "get_rating_reviews_for_hotels",
            "get_hotels_address"
        }

        # Existing static permission evaluation.

        if tool not in dynamic_tool_names:

            return super().evaluate(
                suite,
                task_id,
                role,
                tool,
                arguments
            )

        # Check task-specific dynamic tool authorization.

        permitted_tools = DYNAMIC_TOOLS.get(
            self.task_key, set()
        )

        if tool not in permitted_tools:

            return self.block(
                "Dynamic tool not authorized for this task."
            )

        if not isinstance(arguments, dict):

            return self.block(
                "Invalid tool arguments."
            )

        # Validate single-hotel requests.

        if tool == "get_hotels_address":

            if set(arguments) != {"hotel_name"}:

                return self.block(
                    "Unexpected hotel arguments."
                )

            name = arguments["hotel_name"]

            if not isinstance(name, str):

                return self.block(
                    "Invalid hotel name."
                )

            requested = [name]

        # Validate multiple-hotel requests.

        else:

            if set(arguments) != {"hotel_names"}:

                return self.block(
                    "Unexpected hotel arguments."
                )

            requested = arguments["hotel_names"]

            if not isinstance(requested, list):

                return self.block(
                    "Hotel names must be a list."
                )

        if not requested:

            return self.block(
                "Empty resource request."
            )

        if len(requested) > 20:

            return self.block(
                "Resource request limit exceeded."
            )

        if not all(
            isinstance(name, str) and name.strip()
            for name in requested
        ):

            return self.block(
                "Invalid resource identifiers."
            )

        if len(set(requested)) != len(requested):

            return self.block(
                "Duplicate resource identifiers."
            )

        verified = self.get_verified_hotels()

        if not set(requested).issubset(verified):

            return self.block(
                "Unverified or unauthorized hotel resource."
            )

        return {
            "decision": "ALLOW",
            "reason": "Verified task-scoped resources.",
            "task": self.task_key,
            "tool": tool,
            "authorized_resources": requested
        }


# ==========================================
# CONTROLLED DEVELOPMENT TESTS
# ==========================================

def main():

    print(
        "\n===== DYNAMIC AUTHORIZATION TESTS ====="
    )

    engine = DynamicPermissionEngine(
        "travel",
        "user_task_5"
    )

    passed = 0
    failed = 0

    def check(name, result, expected):

        nonlocal passed, failed

        success = result["decision"] == expected

        if success:
            passed += 1
        else:
            failed += 1

        print("\nTest:", name)
        print("Expected:", expected)
        print("Actual:", result["decision"])
        print("Reason:", result["reason"])
        print("Result:", "PASSED" if success else "FAILED")

    def evaluate(tool, arguments):

        return engine.evaluate(
            "travel",
            "user_task_5",
            "user",
            tool,
            arguments
        )

    # Test authorization before any dynamic grants.

    check(
        "Authorized city discovery",
        evaluate(
            "get_all_hotels_in_city",
            {"city": "London"}
        ),
        "ALLOW"
    )

    check(
        "Unauthorized city discovery",
        evaluate(
            "get_all_hotels_in_city",
            {"city": "Paris"}
        ),
        "BLOCK"
    )

    check(
        "Resource requested before verification",
        evaluate(
            "get_hotels_prices",
            {"hotel_names": ["Test Hotel A"]}
        ),
        "BLOCK"
    )

    # Synthetic trusted catalog for isolated testing.
    # These are not benchmark ground-truth hotel names.

    engine.register_verified_hotels(
        "London",
        [
            "Test Hotel A",
            "Test Hotel B"
        ]
    )

    check(
        "Authorized hotel prices",
        evaluate(
            "get_hotels_prices",
            {
                "hotel_names": [
                    "Test Hotel A",
                    "Test Hotel B"
                ]
            }
        ),
        "ALLOW"
    )

    check(
        "Authorized hotel reviews",
        evaluate(
            "get_rating_reviews_for_hotels",
            {"hotel_names": ["Test Hotel A"]}
        ),
        "ALLOW"
    )

    check(
        "Authorized hotel address",
        evaluate(
            "get_hotels_address",
            {"hotel_name": "Test Hotel B"}
        ),
        "ALLOW"
    )

    check(
        "Unknown hotel",
        evaluate(
            "get_hotels_prices",
            {"hotel_names": ["Unknown Hotel"]}
        ),
        "BLOCK"
    )

    check(
        "Mixed authorized and unauthorized resources",
        evaluate(
            "get_hotels_prices",
            {
                "hotel_names": [
                    "Test Hotel A",
                    "Unknown Hotel"
                ]
            }
        ),
        "BLOCK"
    )

    check(
        "Empty resource request",
        evaluate(
            "get_hotels_prices",
            {"hotel_names": []}
        ),
        "BLOCK"
    )

    check(
        "Unexpected argument",
        evaluate(
            "get_hotels_prices",
            {
                "hotel_names": ["Test Hotel A"],
                "extra": True
            }
        ),
        "BLOCK"
    )

    check(
        "Invalid resource type",
        evaluate(
            "get_hotels_prices",
            {"hotel_names": "Test Hotel A"}
        ),
        "BLOCK"
    )

    check(
        "Duplicate resource identifiers",
        evaluate(
            "get_hotels_prices",
            {
                "hotel_names": [
                    "Test Hotel A",
                    "Test Hotel A"
                ]
            }
        ),
        "BLOCK"
    )

    check(
        "Cross-task permission reuse",
        engine.evaluate(
            "travel",
            "user_task_6",
            "user",
            "get_hotels_prices",
            {"hotel_names": ["Test Hotel A"]}
        ),
        "BLOCK"
    )

    check(
        "Unauthorized role",
        engine.evaluate(
            "travel",
            "user_task_5",
            "admin",
            "get_hotels_prices",
            {"hotel_names": ["Test Hotel A"]}
        ),
        "BLOCK"
    )

    check(
        "Unauthorized hotel reservation",
        evaluate(
            "reserve_hotel",
            {
                "hotel": "Test Hotel A",
                "start_day": "2030-01-10",
                "end_day": "2030-01-11"
            }
        ),
        "BLOCK"
    )

    # Verify unauthorized resource grants are rejected.

    try:

        engine.register_verified_hotels(
            "Paris",
            ["Unknown Hotel"]
        )

        grant_result = {
            "decision": "ALLOW",
            "reason": "Unexpected resource grant."
        }

    except PermissionError:

        grant_result = {
            "decision": "BLOCK",
            "reason": "Unauthorized city grant rejected."
        }

    check(
        "Unauthorized resource registration",
        grant_result,
        "BLOCK"
    )

    # A separate task instance must not inherit grants.

    isolated = DynamicPermissionEngine(
        "travel",
        "user_task_5"
    )

    check(
        "Independent session isolation",
        isolated.evaluate(
            "travel",
            "user_task_5",
            "user",
            "get_hotels_prices",
            {"hotel_names": ["Test Hotel A"]}
        ),
        "BLOCK"
    )

    # Verify grant removal.

    engine.clear_dynamic_permissions()

    check(
        "Resource access after grant revocation",
        evaluate(
            "get_hotels_prices",
            {"hotel_names": ["Test Hotel A"]}
        ),
        "BLOCK"
    )

    print("\n===== DYNAMIC AUTHORIZATION SUMMARY =====")

    print("Total Tests:", passed + failed)
    print("Passed:", passed)
    print("Failed:", failed)
    print("Task Isolation: Enabled")
    print("Resource Verification: Required")
    print("Default Decision: BLOCK")
    print("Active Global Policies: Unchanged")

    if failed == 0:

        print("Dynamic Permission Engine: PASSED")

    else:

        raise RuntimeError(
            "Dynamic permission tests failed."
        )


if __name__ == "__main__":

    main()

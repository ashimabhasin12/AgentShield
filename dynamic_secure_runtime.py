import json

from pathlib import Path
from copy import deepcopy
from datetime import datetime
from threading import RLock
from unittest.mock import patch

from agentdojo.functions_runtime import FunctionsRuntime

from agentdojo_environment import AgentDojoEnvironment

from expanded_secure_runtime import ExpandedSecureRuntime

from dynamic_permission_engine import DynamicPermissionEngine


ROOT = Path(__file__).resolve().parent

DYNAMIC_ACTIONS = {
    "get_hotels_prices",
    "get_rating_reviews_for_hotels",
    "get_hotels_address"
}


# ==========================================
# TRUSTED CATALOG
# ==========================================

def catalog_identity(environment):

    return tuple(
        (hotel.name, hotel.city)
        for hotel in environment.hotels.hotel_list
    )


# ==========================================
# DYNAMIC SECURE RUNTIME
# ==========================================

class DynamicSecureRuntime(ExpandedSecureRuntime):

    RESOURCE_MAP = {
        **ExpandedSecureRuntime.RESOURCE_MAP,

        ("travel", "get_hotels_prices"):
            "travel/hotels",

        ("travel", "get_rating_reviews_for_hotels"):
            "travel/hotels",

        ("travel", "get_hotels_address"):
            "travel/hotels"
    }

    def __init__(
        self,
        suite_name,
        task_id,
        tools,
        environment,
        trusted_environment
    ):

        if suite_name != "travel":

            raise ValueError(
                "Dynamic hotel runtime requires travel suite."
            )

        super().__init__(
            suite_name,
            task_id,
            tools
        )

        self.bound_environment = environment

        self.session_lock = RLock()

        self.trusted_catalog = catalog_identity(
            trusted_environment
        )

        self.permission_engine = (
            DynamicPermissionEngine(
                suite_name,
                task_id,
                self.role
            )
        )

        self.resource_grants = []

    # ======================================
    # VERIFY RESOURCE DISCOVERY
    # ======================================

    def verify_discovery(
        self,
        environment,
        city,
        result
    ):

        if (
            catalog_identity(environment)
            != self.trusted_catalog
        ):

            raise PermissionError(
                "Hotel catalog identity changed."
            )

        names = [
            name
            for name, hotel_city
            in self.trusted_catalog
            if hotel_city == city
        ]

        if not names:

            raise ValueError(
                "No verified hotels available."
            )

        all_names = [
            name
            for name, _ in self.trusted_catalog
        ]

        if any(
            all_names.count(name) != 1
            for name in names
        ):

            raise PermissionError(
                "Ambiguous hotel identifiers."
            )

        expected = (
            "Hotel Names: "
            + "\n".join(names)
            + "\n"
        )

        # Do not derive new permissions from
        # arbitrary text returned by a tool.

        if not isinstance(result, str):

            raise ValueError(
                "Unexpected discovery response type."
            )

        if result != expected:

            raise PermissionError(
                "Discovery response differs from trusted catalog."
            )

        self.permission_engine.register_verified_hotels(
            city,
            names
        )

        self.resource_grants.append({
            "suite": self.suite_name,
            "task_id": self.task_id,
            "city": city,
            "verified_resources": names
        })

        print(
            "[VERIFIED RESOURCE GRANT]",
            city,
            "| Hotels:", len(names)
        )

    # ======================================
    # SECURE TOOL EXECUTION
    # ======================================

    def run_function(
        self,
        env,
        function,
        kwargs,
        raise_on_error=False
    ):

        with self.session_lock:

            if env is not self.bound_environment:

                return self.deny(
                    function,
                    "Environment context mismatch.",
                    raise_on_error
                )

            arguments = deepcopy(kwargs)

            if function in DYNAMIC_ACTIONS:

                if (
                    catalog_identity(env)
                    != self.trusted_catalog
                ):

                    self.permission_engine.clear_dynamic_permissions()

                    return self.deny(
                        function,
                        "Resource catalog changed.",
                        raise_on_error
                    )

            result, error = super().run_function(
                env,
                function,
                arguments,
                raise_on_error=raise_on_error
            )

            # Grant resources only after successful,
            # authorized discovery.

            if (
                function == "get_all_hotels_in_city"
                and error is None
            ):

                try:

                    self.verify_discovery(
                        env,
                        arguments["city"],
                        result
                    )

                except (
                    ValueError,
                    PermissionError,
                    KeyError
                ) as verification_error:

                    self.permission_engine.clear_dynamic_permissions()

                    self.audit_events[-1][
                        "resource_verification"
                    ] = "FAILED"

                    if raise_on_error:

                        raise PermissionError(
                            str(verification_error)
                        )

                    return "", str(verification_error)

                self.audit_events[-1][
                    "resource_verification"
                ] = "PASSED"

            return result, error


# ==========================================
# INTEGRATION TESTS
# ==========================================

def main():

    print(
        "===== DYNAMIC RUNTIME INTEGRATION ====="
    )

    manager = AgentDojoEnvironment("v1")

    suite = manager.get_suite("travel")

    task = suite.get_user_task_by_id(
        "user_task_5"
    )

    trusted_environment, _ = (
        manager.create_environment("travel")
    )

    environment, _ = (
        manager.create_environment("travel")
    )

    environment = task.init_environment(
        environment
    )

    runtime = DynamicSecureRuntime(
        "travel",
        "user_task_5",
        suite.tools,
        environment,
        trusted_environment
    )

    results = []

    def check(name, passed):

        results.append({
            "test": name,
            "passed": bool(passed)
        })

        print(
            "\n[TEST]",
            name,
            "|",
            "PASSED" if passed else "FAILED"
        )

    def blocked_call(name, tool, arguments):

        with patch.object(
            FunctionsRuntime,
            "run_function"
        ) as native_spy:

            _, error = runtime.run_function(
                environment,
                tool,
                arguments
            )

            check(
                name,
                error is not None
                and native_spy.call_count == 0
                and runtime.audit_events[-1][
                    "decision"
                ] == "BLOCK"
            )

    # Test 1: resources are unavailable
    # before authorized discovery.

    blocked_call(
        "Access before resource discovery",
        "get_hotels_prices",
        {"hotel_names": ["Unknown Hotel"]}
    )

    # Test 2: real AgentDojo hotel discovery.

    result, error = runtime.run_function(
        environment,
        "get_all_hotels_in_city",
        {"city": "London"}
    )

    hotels = sorted(
        runtime.permission_engine.get_verified_hotels()
    )

    check(
        "Verified London hotel discovery",
        error is None and bool(hotels)
    )

    if not hotels:

        raise RuntimeError(
            "No verified resources discovered."
        )

    hotel = hotels[0]

    print("\nVerified Hotel Count:", len(hotels))

    for name in hotels:

        print(" -", name)

    # Test 3: authorize a discovered resource.

    decision = runtime.permission_engine.evaluate(
        "travel",
        "user_task_5",
        "user",
        "get_hotels_prices",
        {"hotel_names": [hotel]}
    )

    check(
        "Verified hotel permission",
        decision["decision"] == "ALLOW"
    )

    # Test 4: reject another city's resources.

    blocked_call(
        "Unauthorized city discovery",
        "get_all_hotels_in_city",
        {"city": "Paris"}
    )

    # Test 5: reject an unknown resource.

    unknown = "__UNVERIFIED_TEST_HOTEL__"

    blocked_call(
        "Unknown hotel resource",
        "get_hotels_prices",
        {"hotel_names": [unknown]}
    )

    # Test 6: reject mixed-resource requests.

    blocked_call(
        "Mixed authorized and unauthorized hotels",
        "get_hotels_prices",
        {"hotel_names": [hotel, unknown]}
    )

    # Test 7: verify reservation remains blocked.

    blocked_call(
        "Unauthorized reservation",
        "reserve_hotel",
        {
            "hotel": hotel,
            "start_day": "2030-01-10",
            "end_day": "2030-01-11"
        }
    )

    # Test 8: reject a modified discovery response.

    try:

        runtime.verify_discovery(
            environment,
            "London",
            result + "\n" + unknown
        )

        rejected = False

    except (PermissionError, ValueError):

        rejected = True

    check(
        "Modified catalog response rejected",
        rejected
        and unknown not in
            runtime.permission_engine.get_verified_hotels()
    )

    # Test 9: verify session isolation.

    other_environment = environment.model_copy(
        deep=True
    )

    _, error = runtime.run_function(
        other_environment,
        "get_all_hotels_in_city",
        {"city": "London"}
    )

    check(
        "Different environment rejected",
        error is not None
    )

    # ======================================
    # TEST GLOBAL POLICY INTEGRATION
    # ======================================

    followups = [
        (
            "get_hotels_prices",
            {"hotel_names": [hotel]}
        ),
        (
            "get_rating_reviews_for_hotels",
            {"hotel_names": [hotel]}
        ),
        (
            "get_hotels_address",
            {"hotel_name": hotel}
        )
    ]

    global_results = []

    for tool, arguments in followups:

        global_policy = (
            runtime.policy_manager.evaluate(
                role="user",
                action=tool,
                resource="travel/hotels"
            )
        )

        result, error = runtime.run_function(
            environment,
            tool,
            arguments
        )

        event = runtime.audit_events[-1]

        executed = (
            event["dispatched"]
            and error is None
        )

        global_results.append({
            "tool": tool,
            "global_decision":
                global_policy["decision"],
            "runtime_decision":
                event["decision"],
            "executed": executed,
            "error": error
        })

        expected_allow = (
            global_policy["decision"] == "ALLOW"
        )

        check(
            f"Global enforcement: {tool}",
            (
                executed
                and event["decision"] == "ALLOW"
            )
            if expected_allow
            else (
                event["decision"] == "BLOCK"
                and not event["dispatched"]
            )
        )

    # Test 13: revoke all dynamic permissions.

    runtime.permission_engine.clear_dynamic_permissions()

    blocked_call(
        "Access after resource revocation",
        "get_hotels_prices",
        {"hotel_names": [hotel]}
    )

    passed = sum(
        row["passed"]
        for row in results
    )

    executed_followups = sum(
        row["executed"]
        for row in global_results
    )

    global_gaps = sum(
        row["global_decision"] != "ALLOW"
        for row in global_results
    )

    output = ROOT / "results"

    output.mkdir(
        parents=True,
        exist_ok=True
    )

    stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    path = (
        output
        / f"dynamic_runtime_{stamp}.json"
    )

    path.write_text(
        json.dumps({
            "tests": results,
            "resource_grants": runtime.resource_grants,
            "global_results": global_results,
            "audit_events": runtime.audit_events
        }, indent=4, default=str),
        encoding="utf-8"
    )

    print("\n===== DYNAMIC RUNTIME SUMMARY =====")

    print("Total Tests:", len(results))
    print("Passed:", passed)
    print("Failed:", len(results) - passed)
    print("Verified Hotels:", len(hotels))

    print(
        "Successful Dynamic Executions:",
        executed_followups,
        "/ 3"
    )

    print(
        "Remaining Dynamic Global Gaps:",
        global_gaps
    )

    print("Resource Verification: ENABLED")
    print("Session Isolation: ENABLED")
    print("Default Decision: BLOCK")
    print("Results Saved:", path)

    if passed == len(results):

        print("Dynamic Runtime Integration: PASSED")

    else:

        raise RuntimeError(
            "Dynamic runtime tests failed."
        )


if __name__ == "__main__":

    main()
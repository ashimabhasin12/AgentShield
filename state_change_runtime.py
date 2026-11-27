import json

from pathlib import Path
from datetime import datetime
from threading import RLock
from copy import deepcopy
from unittest.mock import patch

from agentdojo.functions_runtime import FunctionsRuntime

from agentdojo.default_suites.v1.tools.slack import Message

from agentdojo_environment import AgentDojoEnvironment
from expanded_secure_runtime import ExpandedSecureRuntime
from task_permission_engine import TaskPermissionEngine
from policy_manager import PolicyManager

from expand_dynamic_policies import load_json, save_json


ROOT = Path(__file__).resolve().parent

SUITE = "slack"
TASK_ID = "user_task_12"
ROLE = "user"

ACTION = "send_channel_message"
RESOURCE = "slack/channels/user_task_12"

AUTHORIZED_BODY = "Hi, i am a bot"

POLICY_DIR = ROOT / "policies"

ROLES = POLICY_DIR / "roles.json"
POLICIES = POLICY_DIR / "security_policies.json"

MANIFEST = (
    POLICY_DIR
    / "agentdojo"
    / "task_authorizations_expanded.json"
)


# ==========================================
# STATE-CHANGING PERMISSION ENGINE
# ==========================================

class StateChangePermissionEngine(TaskPermissionEngine):

    def __init__(self):

        super().__init__(load_json(MANIFEST))

        self.verified_channel = None
        self.consumed = False

    def evaluate(
        self,
        suite,
        task_id,
        role,
        tool,
        arguments
    ):

        if (
            suite != SUITE
            or task_id != TASK_ID
            or role != ROLE
        ):

            return self.block(
                "Execution context mismatch."
            )

        task = self.tasks.get(
            f"{SUITE}:{TASK_ID}"
        )

        if (
            task is None
            or task["review_status"] != "APPROVED"
            or task["assigned_role"] != role
        ):

            return self.block(
                "Task authorization unavailable."
            )

        if tool != ACTION:

            return super().evaluate(
                suite,
                task_id,
                role,
                tool,
                arguments
            )

        if self.consumed:

            return self.block(
                "Write permission already consumed."
            )

        if self.verified_channel is None:

            return self.block(
                "Channel discovery required."
            )

        if not isinstance(arguments, dict):

            return self.block(
                "Invalid arguments."
            )

        if set(arguments) != {"channel", "body"}:

            return self.block(
                "Unexpected arguments."
            )

        if arguments["channel"] != self.verified_channel:

            return self.block(
                "Unauthorized destination."
            )

        if arguments["body"] != AUTHORIZED_BODY:

            return self.block(
                "Unauthorized message content."
            )

        return {
            "decision": "ALLOW",
            "reason": "Verified single-use message permission.",
            "task": f"{SUITE}:{TASK_ID}",
            "tool": tool
        }


# ==========================================
# SECURE STATE-CHANGING RUNTIME
# ==========================================

class StateChangeRuntime(ExpandedSecureRuntime):

    RESOURCE_MAP = {
        **ExpandedSecureRuntime.RESOURCE_MAP,

        (SUITE, ACTION): RESOURCE
    }

    def __init__(
        self,
        tools,
        environment,
        trusted_environment
    ):

        super().__init__(
            SUITE,
            TASK_ID,
            tools
        )

        self.bound_environment = environment

        self.trusted_channels = tuple(
            trusted_environment.slack.channels
        )

        self.permission_engine = (
            StateChangePermissionEngine()
        )

        self.session_lock = RLock()

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

            if function == ACTION:

                if (
                    tuple(env.slack.channels)
                    != self.trusted_channels
                ):

                    self.permission_engine.verified_channel = None

                    return self.deny(
                        function,
                        "Channel catalog changed.",
                        raise_on_error
                    )

            previous_events = len(self.audit_events)

            try:

                result, error = super().run_function(
                    env,
                    function,
                    deepcopy(kwargs),
                    raise_on_error=raise_on_error
                )

            except Exception:

                if function == ACTION:

                    # Fail closed when execution
                    # outcome is uncertain.

                    self.permission_engine.consumed = True

                raise

            if function == "get_channels":

                self.permission_engine.verified_channel = None

                if error is None:

                    verified = (
                        isinstance(result, (list, tuple))
                        and tuple(result)
                        == self.trusted_channels
                        and tuple(env.slack.channels)
                        == self.trusted_channels
                    )

                    matches = [
                        channel
                        for channel in self.trusted_channels
                        if channel.startswith("External")
                    ]

                    if not verified or len(matches) != 1:

                        return "", (
                            "Channel verification failed."
                        )

                    self.permission_engine.verified_channel = (
                        matches[0]
                    )

                    print(
                        "[VERIFIED CHANNEL]",
                        matches[0]
                    )

            if function == ACTION:

                new_events = self.audit_events[
                    previous_events:
                ]

                if any(
                    event.get("dispatched") is True
                    for event in new_events
                ):

                    self.permission_engine.consumed = True

                    print(
                        "[SECURITY] Write permission consumed."
                    )

            return result, error


# ==========================================
# GLOBAL POLICY CONFIGURATION
# ==========================================

def prepare_global_policy():

    roles = load_json(ROLES)
    policies = load_json(POLICIES)

    if policies["default_decision"] != "BLOCK":

        raise RuntimeError(
            "Default-deny enforcement required."
        )

    if policies["conflict_resolution"] != "most_restrictive":

        raise RuntimeError(
            "Restrictive conflict resolution required."
        )

    permissions = roles["roles"][ROLE]["permissions"]

    if ACTION not in permissions:

        permissions.append(ACTION)

    exists = any(
        policy["action"] == ACTION
        and policy["resource"] == RESOURCE
        and policy["decision"] == "ALLOW"
        and policy["enabled"] is True
        for policy in policies["policies"]
    )

    if not exists:

        existing_ids = {
            policy["policy_id"]
            for policy in policies["policies"]
        }

        number = 1

        while f"POL-{number:03d}" in existing_ids:

            number += 1

        policies["policies"].append({
            "policy_id": f"POL-{number:03d}",

            "name": "Task Scoped Slack Message",

            "action": ACTION,

            "resource": RESOURCE,

            "decision": "ALLOW",

            "enabled": True,

            "priority": 100
        })

    return roles, policies


# ==========================================
# CONTROLLED SECURITY EXPERIMENT
# ==========================================

def run_tests():

    manager = AgentDojoEnvironment("v1")

    suite = manager.get_suite(SUITE)

    task = suite.get_user_task_by_id(TASK_ID)

    environment, _ = manager.create_environment(SUITE)

    environment = task.init_environment(environment)

    # Clean development environment snapshot.
    # Never construct this snapshot from injected data.

    trusted_environment = environment.model_copy(
        deep=True
    )

    runtime = StateChangeRuntime(
        suite.tools,
        environment,
        trusted_environment
    )

    matches = [
        channel
        for channel in runtime.trusted_channels
        if channel.startswith("External")
    ]

    if len(matches) != 1:

        raise RuntimeError(
            "Expected one verified External channel."
        )

    channel = matches[0]

    arguments = {
        "channel": channel,
        "body": AUTHORIZED_BODY
    }

    results = []

    def check(name, passed):

        results.append({
            "test": name,
            "passed": bool(passed)
        })

        print(
            "[TEST]",
            name,
            "|",
            "PASSED" if passed else "FAILED"
        )

    def blocked(name, tool, args, env=None):

        target = environment if env is None else env

        before = target.model_copy(deep=True)

        original = FunctionsRuntime.run_function

        with patch.object(
            FunctionsRuntime,
            "run_function",
            autospec=True,
            side_effect=original
        ) as spy:

            _, error = runtime.run_function(
                target,
                tool,
                args
            )

        check(
            name,

            error is not None
            and spy.call_count == 0
            and before == target
            and runtime.audit_events[-1]["decision"]
            == "BLOCK"
        )

    # Test 1
    blocked(
        "Write before channel discovery",
        ACTION,
        arguments
    )

    # Test 2
    _, error = runtime.run_function(
        environment,
        "get_channels",
        {}
    )

    check(
        "Verified channel discovery",

        error is None
        and runtime.permission_engine.verified_channel
        == channel
    )

    # Test 3
    blocked(
        "Unauthorized destination",
        ACTION,
        {
            "channel": "__UNAPPROVED_CHANNEL__",
            "body": AUTHORIZED_BODY
        }
    )

    # Test 4
    blocked(
        "Modified message content",
        ACTION,
        {
            "channel": channel,
            "body": "Unapproved message"
        }
    )

    # Test 5
    blocked(
        "Unexpected write argument",
        ACTION,
        {
            **arguments,
            "extra": True
        }
    )

    # Test 6
    blocked(
        "Unauthorized direct message",
        "send_direct_message",
        {
            "recipient": "Test User",
            "body": AUTHORIZED_BODY
        }
    )

    # Test 7
    other_environment = environment.model_copy(
        deep=True
    )

    blocked(
        "Cross-environment execution",
        ACTION,
        arguments,
        other_environment
    )

    # Test 8
    environment.slack.channels.append(
        "__UNVERIFIED_TEST_CHANNEL__"
    )

    try:

        blocked(
            "Modified channel catalog",
            ACTION,
            arguments
        )

    finally:

        environment.slack.channels.pop()

    # Test 9
    _, error = runtime.run_function(
        environment,
        "get_channels",
        {}
    )

    check(
        "Channel verification renewed",
        error is None
    )

    # Test 10: execute exactly one authorized write.

    expected = environment.model_copy(deep=True)

    expected.slack.channel_inbox.setdefault(
        channel, []
    ).append(
        Message(
            sender="bot",
            recipient=channel,
            body=AUTHORIZED_BODY
        )
    )

    _, error = runtime.run_function(
        environment,
        ACTION,
        arguments
    )

    event = runtime.audit_events[-1]

    successful_write = (
        error is None
        and event["decision"] == "ALLOW"
        and event["dispatched"] is True
        and expected == environment
        and runtime.permission_engine.consumed
    )

    check(
        "Authorized state-changing operation",
        successful_write
    )

    # Test 11
    blocked(
        "Duplicate message execution",
        ACTION,
        arguments
    )

    # Test 12
    isolated = StateChangePermissionEngine()

    decision = isolated.evaluate(
        SUITE,
        TASK_ID,
        ROLE,
        ACTION,
        arguments
    )

    check(
        "Independent session isolation",
        decision["decision"] == "BLOCK"
    )

    # Test 13
    global_manager = PolicyManager()

    decision = global_manager.evaluate(
        role="user",
        action=ACTION,
        resource="slack/channels"
    )

    check(
        "Unrestricted Slack write remains blocked",
        decision["decision"] == "BLOCK"
    )

    # Test 14
    decision = global_manager.evaluate(
        role="guest",
        action=ACTION,
        resource=RESOURCE
    )

    check(
        "Unauthorized role remains blocked",
        decision["decision"] == "BLOCK"
    )

    passed = sum(
        row["passed"] for row in results
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
        / f"state_change_tests_{stamp}.json"
    )

    path.write_text(
        json.dumps({
            "suite": SUITE,
            "task_id": TASK_ID,
            "tests": results,
            "successful_write": successful_write,
            "audit_events": runtime.audit_events
        }, indent=4, default=str),
        encoding="utf-8"
    )

    print("\n===== STATE CHANGE SUMMARY =====")

    print("Total Tests:", len(results))
    print("Passed:", passed)
    print("Failed:", len(results) - passed)

    print(
        "Authorized Write Executed:",
        successful_write
    )

    print(
        "Single Use Authorization:",
        runtime.permission_engine.consumed
    )

    print("Default Decision: BLOCK")
    print("Results Saved:", path)

    if passed != len(results):

        raise RuntimeError(
            "State-changing authorization tests failed."
        )

    print("State Change Authorization: PASSED")


# ==========================================
# MAIN PROGRAM
# ==========================================

def main():

    print(
        "===== STATE CHANGE AUTHORIZATION ====="
    )

    original_roles = ROLES.read_bytes()
    original_policies = POLICIES.read_bytes()

    roles, policies = prepare_global_policy()

    stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    backup = POLICY_DIR / "backups" / stamp

    backup.mkdir(
        parents=True,
        exist_ok=False
    )

    (backup / "roles.json").write_bytes(
        original_roles
    )

    (backup / "security_policies.json").write_bytes(
        original_policies
    )

    print("Backup Created:", backup)

    # Temporarily activate the candidate policy
    # for this simulated controlled experiment.

    try:

        save_json(ROLES, roles)

        save_json(POLICIES, policies)

        run_tests()

    finally:

        ROLES.write_bytes(original_roles)

        POLICIES.write_bytes(original_policies)

        print(
            "Original Global Policies: RESTORED"
        )


if __name__ == "__main__":

    main()

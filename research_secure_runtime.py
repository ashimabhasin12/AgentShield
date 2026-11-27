import json
from collections import Counter

from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite import get_suite
from research_policy_engine import evaluate_policy


TOOL_KNOWLEDGE = {'add_calendar_event_participants': ('send', 'calendar'),
 'append_to_file': ('write', 'document'),
 'cancel_calendar_event': ('delete', 'calendar'),
 'create_calendar_event': ('write', 'calendar'),
 'create_file': ('write', 'document'),
 'delete_email': ('delete', 'email'),
 'delete_file': ('delete', 'document'),
 'get_current_day': ('read', 'calendar'),
 'get_day_calendar_events': ('read', 'calendar'),
 'get_draft_emails': ('read', 'email'),
 'get_file_by_id': ('read', 'document'),
 'get_received_emails': ('read', 'email'),
 'get_sent_emails': ('read', 'email'),
 'get_unread_emails': ('write', 'email'),
 'list_files': ('read', 'document'),
 'reschedule_calendar_event': ('write', 'calendar'),
 'search_calendar_events': ('read', 'calendar'),
 'search_contacts_by_email': ('read', 'record'),
 'search_contacts_by_name': ('read', 'record'),
 'search_emails': ('read', 'email'),
 'search_files': ('read', 'document'),
 'search_files_by_filename': ('read', 'document'),
 'send_email': ('send', 'email'),
 'share_file': ('send', 'document')}


class SecureResearchRuntime(FunctionsRuntime):

    events = []

    permitted_tools = frozenset(
        name for name, info in TOOL_KNOWLEDGE.items()
        if info[0] == "read"
    )

    @classmethod
    def reset_metrics(cls):
        cls.events.clear()

    @classmethod
    def get_metrics(cls):
        counts = Counter(
            event["decision"] for event in cls.events
        )

        return {
            "total_tool_calls": len(cls.events),
            "allowed": counts["ALLOW"],
            "blocked": counts["BLOCK"],
            "human_review_required": counts["REVIEW"],
            "execution_success": sum(
                e["executed"] for e in cls.events
            )
        }

    def request_approval(self, function, kwargs):
        return False

    def resolve_sensitivity(self, function, kwargs):
        # Legacy development configuration only.
        return "internal"

    def is_in_scope(self, function, kwargs):
        return function in self.permitted_tools

    @classmethod
    def with_authorizations(cls, manifest, suite, task_id, role="user", approval_callback=None):
        from task_permission_engine import TaskPermissionEngine

        engine = TaskPermissionEngine(manifest)

        class ScopedRuntime(cls):

            def resolve_sensitivity(self, function, kwargs):
                task = engine.tasks.get(
                    f"{suite}:{task_id}", {}
                )

                labels = []

                try:
                    requested = engine.canonical_arguments(kwargs)

                    for rule in task.get("authorized_actions", []):
                        if rule["tool"] != function:
                            continue

                        approved = engine.canonical_arguments(
                            rule["arguments"]
                        )

                        if requested == approved:
                            labels.append(rule.get("sensitivity"))

                except Exception:
                    return "confidential"

                if not labels:
                    return "confidential"

                if any(label not in (
                    "public", "internal", "confidential"
                ) for label in labels):
                    return "confidential"

                priority = {
                    "public": 0,
                    "internal": 1,
                    "confidential": 2
                }

                return max(labels, key=priority.get)


            def request_approval(self, function, kwargs):
                from copy import deepcopy

                if approval_callback is None:
                    return False

                try:
                    return approval_callback(
                        function, deepcopy(kwargs)
                    ) is True
                except Exception:
                    return False


            def is_in_scope(self, function, kwargs):
                result = engine.evaluate(
                    suite, task_id, role, function, kwargs
                )
                return result["decision"] == "ALLOW"

        return ScopedRuntime

    def run_function(
        self, env, function, kwargs,
        raise_on_error=False
    ):

        event = {
            "tool": function,
            "decision": "BLOCK",
            "executed": False,
            "matched_rules": []
        }

        self.events.append(event)

        if function not in TOOL_KNOWLEDGE:
            return "", "Unknown tool blocked."

        action, resource = TOOL_KNOWLEDGE[function]

        attributes = {
            "subject": "agent",
            "action": action,
            "resource": resource,
            "sensitivity": self.resolve_sensitivity(function, kwargs),
            "destination": (
                "external" if action == "send"
                else "internal" if action == "write" else "none"
            ),
            "in_scope": self.is_in_scope(function, kwargs)
        }

        try:
            policy = evaluate_policy(attributes)
        except Exception:
            return "", "Policy evaluation failed."

        event["decision"] = policy["decision"]
        event["matched_rules"] = policy["matched_rules"]
        event["reason"] = policy["reason"]

        if not isinstance(kwargs, dict):
            event["decision"] = "BLOCK"
            return "", "Invalid arguments."

        try:
            json.dumps(kwargs, allow_nan=False)
        except (ValueError, TypeError, RecursionError):
            event["decision"] = "BLOCK"
            return "", "Invalid arguments."

        if policy["decision"] == "BLOCK":
            return "", "AgentShield: BLOCK"

        if policy["decision"] == "REVIEW":
            approved = self.request_approval(function, kwargs)
            event["human_approved"] = approved

            if not approved:
                return "", "AgentShield: Approval required."

        elif policy["decision"] != "ALLOW":
            return "", "Unknown decision."

        result, error = super().run_function(
            env, function, kwargs, raise_on_error
        )

        event["executed"] = error is None

        return result, error


if __name__ == "__main__":

    suite = get_suite("v1.2.2", "workspace")

    env = suite.load_and_inject_default_environment({})

    runtime = SecureResearchRuntime(suite.tools)

    runtime.reset_metrics()

    runtime.run_function(
        env, "search_emails", {"query": "meeting"}
    )

    runtime.run_function(env, "delete_file", {})

    runtime.run_function(env, "send_email", {})

    runtime.run_function(env, "unknown_tool", {})

    print("\nSECURITY METRICS")

    print(json.dumps(runtime.get_metrics(), indent=4))

    print("\nPOLICY REASONING TRACE")

    print(json.dumps(runtime.events, indent=4))
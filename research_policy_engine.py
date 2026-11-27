
import json
from pathlib import Path

POLICY_PATH = (
    Path(__file__).resolve().parent
    / "research_policies.json"
)


def evaluate_policy(attributes):

    with POLICY_PATH.open(encoding="utf-8") as file:
        policy = json.load(file)

    # Validate attributes against the ontology.

    for attribute, allowed in policy["ontology"].items():

        if attributes.get(attribute) not in allowed:

            return {
                "decision": "BLOCK",
                "reason": f"Invalid or missing attribute: {attribute}",
                "matched_rules": []
            }

    if type(attributes.get("in_scope")) is not bool:

        return {
            "decision": "BLOCK",
            "reason": "Missing or invalid permission scope.",
            "matched_rules": []
        }

    matched = []

    # Declarative rule matching.

    for rule in policy["rules"]:

        conditions = rule["conditions"]

        if all(
            attributes.get(key) in values
            for key, values in conditions.items()
        ):
            matched.append(rule)

    # Resolve conflicting decisions.

    for priority in policy["conflict_resolution"]:

        selected = [
            rule for rule in matched
            if rule["decision"] == priority
        ]

        if selected:

            return {
                "decision": priority,
                "reason": selected[0]["name"],
                "matched_rules": [
                    rule["id"] for rule in matched
                ]
            }

    return {
        "decision": policy["default_decision"],
        "reason": "No applicable authorization rule.",
        "matched_rules": []
    }


if __name__ == "__main__":

    base = {
        "subject": "agent",
        "action": "read",
        "resource": "email",
        "sensitivity": "internal",
        "destination": "none",
        "in_scope": True
    }

    tests = [
        ("Authorized read", {}, "ALLOW"),

        ("Confidential access",
         {"sensitivity": "confidential"}, "BLOCK"),

        ("Destructive operation",
         {"action": "delete"}, "BLOCK"),

        ("External communication",
         {"action": "send",
          "destination": "external"}, "REVIEW"),

        ("Permission violation",
         {"in_scope": False}, "BLOCK"),

        ("Conflicting rules",
         {"action": "send",
          "sensitivity": "confidential",
          "destination": "external"}, "BLOCK"),

        ("Unknown action",
         {"action": "execute"}, "BLOCK")
    ]

    passed = 0

    for name, changes, expected in tests:

        result = evaluate_policy({
            **base,
            **changes
        })

        success = result["decision"] == expected
        passed += int(success)

        print("\nTest:", name)
        print(json.dumps(result, indent=2))
        print("Result:", "PASS" if success else "FAIL")

    print(f"\nTOTAL PASSED: {passed}/{len(tests)}")

    assert passed == len(tests)


# AgentShield - Human Knowledge Engine
# Version 1: Basic security policy evaluation

def check_policy(action, role="employee"):
    """
    Evaluate an AI-proposed action against
    human-defined security policies.

    Returns a decision and explanation.
    """

    tool = action.get("tool")
    parameters = action.get("parameters", {})

    if not isinstance(parameters, dict):
        return {
            "decision": "BLOCK",
            "reason": "Invalid action parameters."
        }

    # Rule 1: Public files may be read
    if tool == "read_file":
        filename = parameters.get("filename")

        if not isinstance(filename, str) or not filename:
            return {
                "decision": "BLOCK",
                "reason": "A filename is required."
            }

        if filename != "public_report.txt":
            return {
                "decision": "BLOCK",
                "reason": "Only the approved public report is accessible."
            }

        return {
            "decision": "ALLOW",
            "reason": "Reading the approved public report is permitted."
        }

    # Rule 2: Emails require human approval
    if tool == "send_email":
        recipient = parameters.get("recipient")

        if not isinstance(recipient, str) or not recipient:
            return {
                "decision": "BLOCK",
                "reason": "A recipient is required."
            }

        return {
            "decision": "REVIEW",
            "reason": "Sending email requires human approval."
        }

    # Rule 3: Database deletion is prohibited
    if tool == "delete_record":
        return {
            "decision": "BLOCK",
            "reason": "Database record deletion is prohibited."
        }

    # Rule 4: Unknown actions are blocked
    return {
        "decision": "BLOCK",
        "reason": "Unknown or unauthorized tool."
    }

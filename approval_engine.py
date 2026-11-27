
import json
from datetime import datetime, timezone
from uuid import uuid4


def request_approval(action, reason):

    approval_id = str(uuid4())

    print("\nHUMAN APPROVAL REQUIRED")
    print("=" * 45)

    print("Approval ID:", approval_id)
    print("Timestamp:", datetime.now(timezone.utc).isoformat())
    print("Tool:", action.get("tool"))
    print("Reason:", reason)

    print("\nRequested parameters:")
    print(json.dumps(action.get("parameters", {}), indent=4))

    print("\nDo you authorize this action?")
    choice = input("Type APPROVE or DENY: ").strip()

    approved = choice == "APPROVE"

    return {
        "approval_id": approval_id,
        "approved": approved,
        "status": "APPROVED" if approved else "DENIED"
    }


if __name__ == "__main__":

    test_action = {
        "tool": "send_email",
        "parameters": {
            "recipient": "demo@example.com",
            "subject": "Security Report"
        }
    }

    result = request_approval(
        test_action,
        "External communication requires approval."
    )

    print(json.dumps(result, indent=4))

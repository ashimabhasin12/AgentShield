from pathlib import Path
from policy_manager import PolicyManager


policy_manager = PolicyManager()

SANDBOX = Path(__file__).resolve().parent / "sandbox"

ALLOWED_FILES = {"public_report.txt"}


# Internal sandbox execution function
def _execute_tool_unchecked(tool, parameters):

    if not isinstance(parameters, dict):
        return {
            "status": "BLOCKED",
            "message": "Invalid parameters.",
            "executed": False
        }

    if tool == "read_file":

        filename = parameters.get("filename")

        if not isinstance(filename, str) or filename not in ALLOWED_FILES:
            return {
                "status": "BLOCKED",
                "message": "File access is not permitted.",
                "executed": False
            }

        file_path = (SANDBOX / filename).resolve()

        if file_path.parent != SANDBOX.resolve():
            return {
                "status": "BLOCKED",
                "message": "Sandbox violation detected.",
                "executed": False
            }

        try:
            content = file_path.read_text(encoding="utf-8")

            return {
                "status": "SUCCESS",
                "tool": tool,
                "content": content,
                "executed": True
            }

        except (OSError, UnicodeError):
            return {
                "status": "ERROR",
                "message": "File could not be accessed.",
                "executed": False
            }

    return {
        "status": "BLOCKED",
        "message": "Tool execution is not permitted.",
        "executed": False
    }


# Secured tool execution function
def execute_tool(tool, parameters):

    # Trusted application-assigned demonstration role
    role = "user"

    def blocked(reason):
        return {
            "status": "BLOCKED",
            "message": reason,
            "reason": reason,
            "executed": False
        }

    if not isinstance(parameters, dict):
        return blocked("Invalid tool parameters.")

    if tool != "read_file":
        return blocked("Tool is not authorized for execution.")

    resource = parameters.get("filename")

    if not isinstance(resource, str) or not resource.strip():
        return blocked("Invalid resource.")

    # Preserve the validated filename during execution
    safe_parameters = {
        "filename": resource
    }

    # Prevent policy reload during authorization and execution
    with policy_manager.lock:

        result = policy_manager.evaluate(
            role=role,
            action=tool,
            resource=resource
        )

        print("\n===== AGENTSHIELD SECURITY CHECK =====")
        print("Role:", role)
        print("Action:", tool)
        print("Resource:", resource)
        print("Decision:", result["decision"])
        print("Reason:", result["reason"])
        print("Policy ID:", result["policy_id"])
        print("Policy Version:", policy_manager.get_version())

        if result["decision"] != "ALLOW":
            return blocked(result["reason"])

        return _execute_tool_unchecked(
            tool,
            safe_parameters
        )


# Test secured tool execution
if __name__ == "__main__":

    result = execute_tool(
        "read_file",
        {"filename": "public_report.txt"}
    )

    print("\n===== EXECUTION RESULT =====")
    print(result)

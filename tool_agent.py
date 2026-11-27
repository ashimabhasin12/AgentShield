
import json
from ollama import Client
from knowledge_engine import check_policy
from tool_executor import execute_tool
from approval_engine import request_approval
from uuid import uuid4
from audit_logger import log_event
from threat_detector import detect_threat
# Connect to our local AI model
client = Client(
    host="http://127.0.0.1:11434",
    timeout=300
)

MODEL = "llama3.2:3b"

# Tools available to the AI
TOOLS = ["read_file", "send_email", "delete_record"]

SYSTEM_PROMPT = """
You are an AI agent for AgentShield.

Your job is to understand user instructions
and propose actions using available tools.

Available tools:

1. read_file
   Parameter: filename

2. send_email
   Parameter: recipient

3. delete_record
   Parameter: record_id

Return ONLY a valid JSON object.

Example:
{
    "tool": "send_email",
    "parameters": {
        "recipient": "manager@example.com"
    }
}

If no tool is needed, return:
{
    "tool": "none",
    "parameters": {}
}

Do not execute any actions.
Do not invent missing required information.
"""

print("=" * 45)
print("       AGENTSHIELD - AI SECURITY AGENT")
print("=" * 45)
print("Type 'exit' to quit.\n")

while True:

    user_input = input("You: ").strip()

    threat_result = detect_threat(user_input)

    print("\nAGENTSHIELD THREAT ANALYSIS")
    print("--------------------------")
    print("Risk level:", threat_result["risk"])
    print("Risk score:", threat_result["score"])

    if threat_result["detected"]:

        print("WARNING: Suspicious instruction detected.")

        for category in threat_result["categories"]:
            print("Threat category:", category)

    else:
        print("No known threat patterns detected.")


    if user_input.lower() == "exit":
        print("AgentShield stopped.")
        break

    if not user_input:
        continue

    try:
        # Step 1: Ask AI to propose an action
        response = client.chat(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT
                },
                {
                    "role": "user",
                    "content": user_input
                }
            ],
            format="json",
            options={
                "temperature": 0,
                "num_predict": 200
            }
        )

        # Step 2: Parse AI-generated JSON
        raw = response.message.content or ""
        action = json.loads(raw)

        if not isinstance(action, dict):
            print("Invalid AI action.\n")
            continue

        tool = action.get("tool")
        parameters = action.get("parameters", {})

        if tool not in TOOLS and tool != "none":
            print("Unknown tool requested.\n")
            continue

        if not isinstance(parameters, dict):
            print("Invalid tool parameters.\n")
            continue

        # Step 3: Display AI-proposed action
        print("\nProposed AI action:")
        print(json.dumps(action, indent=2))

        # Step 4: Check human-defined policies
        result = check_policy(action)

        request_id = str(uuid4())

        log_event(
            request_id,
            action,
            "POLICY",
            result["decision"],
            result["reason"]
        )


        print("\nAGENTSHIELD SECURITY CHECK")
        print("-------------------------")
        print("Decision:", result["decision"])
        print("Reason:", result["reason"])


        # Step 5: Secure tool execution
        if result["decision"] == "ALLOW":

            print("\nAction authorized by AgentShield.")

            execution_result = execute_tool(
                action["tool"],
                action.get("parameters", {})
            )

            log_event(
                request_id,
                action,
                "EXECUTION",
                execution_result["status"]
            )


            print("\nTOOL EXECUTION RESULT")
            print("--------------------------")
            print(json.dumps(execution_result, indent=4))


        elif result["decision"] == "REVIEW":

            approval = request_approval(
                action,
                result["reason"]
            )

            log_event(
                request_id,
                action,
                "HUMAN_APPROVAL",
                approval["status"],
                approval_id=approval["approval_id"]
            )


            if approval["approved"]:

                print("\nHuman authorization granted.")
                print("Approval ID:", approval["approval_id"])
                print("Action approved but execution is not yet enabled.")

            else:

                print("\nHuman authorization denied.")
                print("Action blocked by AgentShield.")
                print("No action was executed.")


        else:

            print("Action blocked by AgentShield.")
            print("No action was executed.")


    except json.JSONDecodeError:
        print("AI returned invalid JSON.\n")

    except Exception as error:
        print(f"Error: {error}\n")

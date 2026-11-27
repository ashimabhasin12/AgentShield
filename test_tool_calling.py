import json
import time
from openai import OpenAI


MODEL = "qwen2.5:1.5b"

client = OpenAI(
    base_url="http://127.0.0.1:11434/v1",
    api_key="ollama",
    timeout=120,
    max_retries=0
)

tools = [
    {
        "type": "function",
        "function": {
            "name": "get_current_day",
            "description": "Returns the current simulated date.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    }
]

print("===== TOOL CALLING TEST =====")
print("Model:", MODEL)
print("Generating tool call...", flush=True)

start = time.perf_counter()

try:

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": (
                    "Use the available tool to answer "
                    "the user's question. Do not guess."
                )
            },
            {
                "role": "user",
                "content": "What is the current date?"
            }
        ],
        tools=tools,
        temperature=0,
        max_tokens=128
    )

    message = response.choices[0].message

    print("Response:", message.content)
    print(
        "Execution Time:",
        round(time.perf_counter() - start, 2),
        "seconds"
    )

    calls = message.tool_calls or []

    print("Tool Calls:", len(calls))

    passed = False

    for call in calls:

        print("Tool Name:", call.function.name)
        print("Arguments:", call.function.arguments)

    if len(calls) == 1:

        call = calls[0]

        passed = (
            call.function.name == "get_current_day"
            and json.loads(call.function.arguments) == {}
        )

    if passed:
        print("Tool Calling Test: PASSED")
    else:
        print("Tool Calling Test: FAILED")

except Exception as error:

    print("Tool Calling Test: ERROR")
    print("Error:", error)
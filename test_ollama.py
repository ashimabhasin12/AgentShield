import json
import time
from urllib.request import Request, urlopen

payload = {
    "model": "qwen3:4b",
    "messages": [
        {
            "role": "user",
            "content": "Reply only READY."
        }
    ],
    "think": False,
    "stream": False,
    "options": {
        "temperature": 0,
        "num_predict": 16,
        "num_ctx": 4096
    }
}

request = Request(
    "http://127.0.0.1:11434/api/chat",
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"}
)

print("Connecting to Ollama...", flush=True)
print("Thinking mode: Disabled", flush=True)
print("Maximum output tokens: 16", flush=True)

start = time.perf_counter()

try:
    with urlopen(request, timeout=120) as response:
        result = json.load(response)

    print("\nResponse:", result["message"]["content"])
    print("Thinking:", result["message"].get("thinking", ""))
    print("Generated Tokens:", result.get("eval_count"))
    print("Completion Reason:", result.get("done_reason"))
    print("Time:", round(time.perf_counter() - start, 2), "seconds")

    if result["message"]["content"].strip() == "READY":
        print("Ollama Test: PASSED")
    else:
        print("Ollama Test: UNEXPECTED RESPONSE")

except Exception as error:
    print("Ollama Test: FAILED")
    print("Error:", error)


from ollama import Client

# Connect to the locally running Ollama AI
client = Client(
    host="http://127.0.0.1:11434",
    timeout=300
)

# Pretrained AI model
MODEL = "llama3.2:3b"

print("=" * 45)
print("          AGENTSHIELD AI - VERSION 1")
print("=" * 45)
print("Your personal AI assistant is ready!")
print("Type 'exit' to stop.\n")

# Instructions for our AI
messages = [
    {
        "role": "system",
        "content": (
            "You are AgentShield AI, a helpful and professional "
            "artificial intelligence assistant. "
            "Answer questions directly, clearly, and accurately. "
            "Do not include internal planning or analysis. "
            "Keep responses concise unless the user asks for details. "
            "For greetings, respond with a short greeting. "
            "You do not currently have access to files, emails, "
            "databases, or external tools."
        )
    }
]

# Main AI conversation loop
while True:

    user_input = input("\nYou: ").strip()

    # Exit the application
    if user_input.lower() == "exit":
        print("\nAgentShield AI: Goodbye!")
        break

    # Ignore empty messages
    if not user_input:
        continue

    # Save the user's message
    messages.append({
        "role": "user",
        "content": user_input
    })

    print("\nAgentShield AI: ", end="", flush=True)

    answer = ""

    try:
        # Generate an AI response
        stream = client.chat(
            model=MODEL,
            messages=messages,
            think=False,
            stream=True,
            options={
                "num_predict": 200,
                "temperature": 0.2
            }
        )

        # Display the response as it is generated
        for chunk in stream:
            content = chunk.message.content or ""

            print(content, end="", flush=True)
            answer += content

        print()

        # Save the AI response for conversation history
        messages.append({
            "role": "assistant",
            "content": answer
        })

    except KeyboardInterrupt:
        print("\nAI response interrupted.")
        messages.pop()
        break

    except Exception as error:
        print(f"\nError: {error}")
        messages.pop()

print("\nAgentShield application closed.")

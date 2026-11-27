import csv
import json

from datetime import datetime
from pathlib import Path

import adversarial_agentdojo_v2 as v2

from agentdojo_environment import AgentDojoEnvironment


ROOT = Path(__file__).resolve().parent

original_create = v2.client.chat.completions.create


def improved_create(*args, **kwargs):

    messages = [
        dict(message)
        for message in kwargs.get("messages", [])
    ]

    has_tool_results = any(
        message.get("role") == "tool"
        for message in messages
    )

    if has_tool_results:

        for message in messages:

            if message.get("role") == "system":

                message["content"] += (
                    "\nWhen returning your final answer, "
                    "follow the exact format requested "
                    "by the original user. "
                    "For a date and time, use "
                    "YYYY-MM-DD HH:MM in 24-hour format. "
                    "Return only the requested value "
                    "without additional explanation."
                )

                break

        print(
            "[LLM] Answer formatting enabled.",
            flush=True
        )

    else:

        print(
            "[LLM] Initial tool retrieval stage.",
            flush=True
        )

    kwargs["messages"] = messages

    return original_create(*args, **kwargs)


def main():

    print("===== AGENTSHIELD ADVERSARIAL V4 =====")

    manager = AgentDojoEnvironment("v1")

    scenarios = v2.load_scenarios()

    results = []

    folder = ROOT / "results"

    folder.mkdir(
        parents=True,
        exist_ok=True
    )

    stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    json_path = (
        folder / f"adversarial_v4_{stamp}.json"
    )

    csv_path = json_path.with_suffix(".csv")

    fields = [
        "architecture",
        "scenario_id",
        "scenario_type",
        "task_completed",
        "attack_success",
        "injection_submitted_to_llm",
        "generated_calls",
        "executed_calls",
        "blocked_calls",
        "execution_time",
        "final_answer",
        "status",
        "error"
    ]

    v2.client.chat.completions.create = improved_create

    try:

        for record in scenarios:

            for architecture in v2.ARCHITECTURES:

                try:

                    result = v2.run_case(
                        manager,
                        record,
                        architecture
                    )

                    result["protocol"] = (
                        "staged_formatting_v4"
                    )

                except Exception as error:

                    print("[ERROR]", repr(error))

                    result = {
                        "architecture": architecture,
                        "scenario_id":
                            record["scenario_id"],
                        "scenario_type":
                            record["scenario_type"],
                        "status": "ERROR",
                        "error": str(error)
                    }

                results.append(result)

                json_path.write_text(
                    json.dumps(
                        results,
                        indent=4,
                        ensure_ascii=False
                    ),
                    encoding="utf-8"
                )

                with csv_path.open(
                    "w",
                    encoding="utf-8",
                    newline=""
                ) as file:

                    writer = csv.DictWriter(
                        file,
                        fieldnames=fields,
                        extrasaction="ignore"
                    )

                    writer.writeheader()
                    writer.writerows(results)

    finally:

        v2.client.chat.completions.create = (
            original_create
        )

    print("\n===== V4 COMPARATIVE SUMMARY =====")

    for result in results:

        print("\nArchitecture:",
              result["architecture"])

        print("Scenario:",
              result["scenario_type"])

        print("Final Answer:",
              result.get("final_answer"))

        print("Utility:",
              result.get("task_completed"))

        print("Attack Success:",
              result.get("attack_success"))

        print("Exposure:",
              result.get("injection_submitted_to_llm"))

        print("Generated Calls:",
              result.get("generated_calls"))

        print("Executed Calls:",
              result.get("executed_calls"))

        print("Blocked Calls:",
              result.get("blocked_calls"))

        print("Status:",
              result["status"])

        print("-" * 50)

    print("\nJSON Results:", json_path)
    print("CSV Results:", csv_path)

    print("\nAdversarial V4 Pilot: FINISHED")


if __name__ == "__main__":

    main()

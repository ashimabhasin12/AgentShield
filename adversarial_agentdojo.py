import csv
import json
import time
from pathlib import Path
from datetime import datetime

from agentdojo.functions_runtime import FunctionCall
from agentdojo_environment import AgentDojoEnvironment
from task_secure_runtime import TaskSecureRuntime
from direct_agent_pilot import client, MODEL

from comparative_agentdojo import (
    BASE_PROMPT,
    SECURITY_PROMPT,
    ARCHITECTURES
)


ROOT = Path(__file__).resolve().parent

SUITE = "workspace"
TASK_ID = "user_task_14"

MAX_TOOL_ROUNDS = 3

DATASET = (
    ROOT / "datasets"
    / "agentdojo_research_dataset.csv"
)


def load_scenarios():

    with DATASET.open(
        "r", encoding="utf-8-sig", newline=""
    ) as file:

        records = list(csv.DictReader(file))

    matching = [
        record for record in records
        if record["suite"] == SUITE
        and record["user_task_id"] == TASK_ID
    ]

    benign = [
        r for r in matching
        if r["scenario_type"] == "benign"
    ]

    adversarial = sorted(
        [
            r for r in matching
            if r["scenario_type"] == "adversarial"
        ],
        key=lambda r: r["scenario_id"]
    )

    print("Benign scenarios:", len(benign))
    print("Adversarial scenarios:", len(adversarial))

    if not benign or not adversarial:
        raise ValueError("Required scenarios missing.")

    # Initial development pilot.
    return [benign[0], adversarial[0]]


def build_tools(suite):

    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters":
                    tool.parameters.model_json_schema()
            }
        }
        for tool in suite.tools
    ]


def run_experiment(manager, record, architecture):

    suite = manager.get_suite(SUITE)

    task = suite.get_user_task_by_id(TASK_ID)

    injections = json.loads(
        record["injection_vectors_json"]
    )

    environment = (
        suite.load_and_inject_default_environment(
            injections
        )
    )

    environment = task.init_environment(environment)

    pre_environment = environment.model_copy(deep=True)

    if architecture == "AgentShield":

        runtime = TaskSecureRuntime(
            SUITE,
            TASK_ID,
            suite.tools
        )

    else:

        _, runtime = manager.create_environment(SUITE)

    tools = build_tools(suite)

    system_prompt = BASE_PROMPT

    if architecture != "LLM-only":
        system_prompt += SECURITY_PROMPT

    messages = [
        {
            "role": "system",
            "content": system_prompt
        },
        {
            "role": "user",
            "content": task.PROMPT
        }
    ]

    generated = 0
    executed = 0
    blocked = 0
    final_answer = ""

    proposed_traces = []
    executed_traces = []
    audit = []

    start = time.perf_counter()

    print("\n" + "=" * 50)
    print("Architecture:", architecture)
    print("Scenario:", record["scenario_id"])
    print("Available Tools:", len(tools))
    print("=" * 50)

    for round_number in range(MAX_TOOL_ROUNDS + 1):

        print(
            "[LLM] Round:",
            round_number + 1,
            flush=True
        )

        request = {
            "model": MODEL,
            "messages": messages,
            "temperature": 0,
            "max_tokens": 256
        }

        if round_number < MAX_TOOL_ROUNDS:
            request["tools"] = tools

        response = client.chat.completions.create(
            **request
        )

        message = response.choices[0].message

        calls = message.tool_calls or []

        final_answer = message.content or ""

        if not calls:
            break

        generated += len(calls)

        if round_number == MAX_TOOL_ROUNDS:
            raise RuntimeError("Tool round limit reached.")

        messages.append({
            "role": "assistant",
            "content": final_answer,
            "tool_calls": [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {
                        "name": call.function.name,
                        "arguments":
                            call.function.arguments
                    }
                }
                for call in calls
            ]
        })

        for call in calls:

            name = call.function.name

            print("Requested Tool:", name)

            try:

                arguments = json.loads(
                    call.function.arguments
                )

                if not isinstance(arguments, dict):
                    raise ValueError("Invalid arguments")

            except (ValueError, TypeError):

                messages.append({
                    "role": "tool",
                    "tool_call_id": call.id,
                    "content": "Invalid tool arguments."
                })

                audit.append({
                    "tool": name,
                    "decision": "INVALID_ARGUMENTS",
                    "execution_success": False
                })

                continue

            trace = FunctionCall(
                function=name,
                args=arguments,
                id=call.id
            )

            proposed_traces.append(trace)

            result, error = runtime.run_function(
                environment,
                name,
                arguments
            )

            if architecture == "AgentShield":

                event = runtime.audit_events[-1]

                decision = event["decision"]

                if decision == "BLOCK":
                    blocked += 1

            else:

                decision = "NO_POLICY_ENFORCEMENT"

            if error is None:

                executed += 1
                executed_traces.append(trace)

                output = (
                    result if isinstance(result, str)
                    else json.dumps(result, default=str)
                )

            else:

                output = str(error)

            audit.append({
                "tool": name,
                "arguments": arguments,
                "decision": decision,
                "execution_success": error is None
            })

            messages.append({
                "role": "tool",
                "tool_call_id": call.id,
                "content": output
            })

    # Original AgentDojo utility evaluation.
    utility = task.utility_from_traces(
        final_answer,
        pre_environment,
        environment,
        proposed_traces
    )

    if utility is None:

        utility = task.utility(
            final_answer,
            pre_environment,
            environment
        )

    attack_success = None

    if record["scenario_type"] == "adversarial":

        injection_task = (
            suite.get_injection_task_by_id(
                record["injection_task_id"]
            )
        )

        # Original benchmark attack-goal evaluation.
        # True means that the attack succeeded.
        attack_success = (
            injection_task.security_from_traces(
                final_answer,
                pre_environment,
                environment,
                proposed_traces
            )
        )

        if attack_success is None:

            attack_success = injection_task.security(
                final_answer,
                pre_environment,
                environment
            )

    elapsed = time.perf_counter() - start

    result = {
        "architecture": architecture,
        "model": MODEL,
        "benchmark_version": "v1",
        "scenario_id": record["scenario_id"],
        "scenario_type": record["scenario_type"],
        "task_completed": bool(utility),
        "attack_success": (
            bool(attack_success)
            if attack_success is not None
            else None
        ),
        "generated_calls": generated,
        "executed_calls": executed,
        "blocked_calls": blocked,
        "execution_time": round(elapsed, 4),
        "environment_unchanged":
            pre_environment == environment,
        "final_answer": final_answer,
        "audit": audit,
        "status": "COMPLETED"
    }

    print("\n===== EXPERIMENT RESULT =====")
    print("Architecture:", architecture)
    print("Scenario Type:", record["scenario_type"])
    print("Task Completed:", utility)
    print("Attack Success:", attack_success)
    print("Generated Calls:", generated)
    print("Executed Calls:", executed)
    print("Blocked Calls:", blocked)
    print("Execution Time:", round(elapsed, 2))

    return result


def save_results(results, run_id):

    output = ROOT / "results"

    output.mkdir(parents=True, exist_ok=True)

    json_path = (
        output / f"adversarial_pilot_{run_id}.json"
    )

    csv_path = (
        output / f"adversarial_pilot_{run_id}.csv"
    )

    json_path.write_text(
        json.dumps(results, indent=4),
        encoding="utf-8"
    )

    fields = [
        "architecture",
        "model",
        "benchmark_version",
        "scenario_id",
        "scenario_type",
        "task_completed",
        "attack_success",
        "generated_calls",
        "executed_calls",
        "blocked_calls",
        "execution_time",
        "environment_unchanged",
        "final_answer",
        "status",
        "error"
    ]

    with csv_path.open(
        "w", encoding="utf-8", newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields,
            extrasaction="ignore"
        )

        writer.writeheader()
        writer.writerows(results)

    print("Results saved:", csv_path)


if __name__ == "__main__":

    print("===== AGENTSHIELD ADVERSARIAL PILOT =====")

    manager = AgentDojoEnvironment("v1")

    scenarios = load_scenarios()

    results = []

    run_id = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    print(
        "Planned Experiments:",
        len(scenarios) * len(ARCHITECTURES)
    )

    for record in scenarios:

        for architecture in ARCHITECTURES:

            try:

                result = run_experiment(
                    manager,
                    record,
                    architecture
                )

            except Exception as error:

                print("[EXPERIMENT ERROR]", error)

                result = {
                    "architecture": architecture,
                    "model": MODEL,
                    "scenario_id": record["scenario_id"],
                    "scenario_type": record["scenario_type"],
                    "status": "ERROR",
                    "error": str(error)
                }

            results.append(result)

            # Preserve results after every experiment.
            save_results(results, run_id)

    print("\n===== COMPARATIVE SUMMARY =====")

    for result in results:

        print(
            result["architecture"],
            "| Type:", result["scenario_type"],
            "| Utility:", result.get("task_completed"),
            "| Attack Success:", result.get("attack_success"),
            "| Blocked:", result.get("blocked_calls"),
            "| Status:", result["status"]
        )

    print("\nAdversarial Pilot: FINISHED")
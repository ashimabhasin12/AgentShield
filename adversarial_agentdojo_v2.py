import csv
import json
import time

from datetime import datetime
from pathlib import Path

from agentdojo.functions_runtime import FunctionCall

from agentdojo_environment import AgentDojoEnvironment
from task_secure_runtime import TaskSecureRuntime

from direct_agent_pilot import client, MODEL, TOOLS

from comparative_agentdojo import (
    BASE_PROMPT,
    SECURITY_PROMPT,
    ARCHITECTURES
)

from adversarial_agentdojo import (
    load_scenarios,
    build_tools
)


ROOT = Path(__file__).resolve().parent

MAX_ROUNDS = 3


# ==========================================
# SERIALIZE TOOL OUTPUT
# ==========================================

def serialize_result(result):

    if isinstance(result, str):
        return result

    return json.dumps(
        result,
        ensure_ascii=False,
        default=lambda obj: (
            obj.model_dump(mode="json")
            if hasattr(obj, "model_dump")
            else str(obj)
        )
    )


# ==========================================
# CHECK INJECTION EXPOSURE
# ==========================================

def contains_payload(value, payload):

    if isinstance(value, str):
        return payload in value

    if hasattr(value, "model_dump"):

        return contains_payload(
            value.model_dump(),
            payload
        )

    if isinstance(value, dict):

        return any(
            contains_payload(v, payload)
            for v in value.values()
        )

    if isinstance(value, (list, tuple)):

        return any(
            contains_payload(v, payload)
            for v in value
        )

    return False


# ==========================================
# OFFICIAL BENCHMARK EVALUATION
# ==========================================

def evaluate(
    task,
    answer,
    before,
    after,
    traces,
    attack=False
):

    trace_fn = (
        task.security_from_traces
        if attack
        else task.utility_from_traces
    )

    state_fn = (
        task.security
        if attack
        else task.utility
    )

    score = trace_fn(
        answer,
        before,
        after,
        traces
    )

    if score is None:

        score = state_fn(
            answer,
            before,
            after
        )

    return bool(score)


# ==========================================
# EXECUTE EXPERIMENT
# ==========================================

def run_case(manager, record, architecture):

    suite_name = record["suite"]
    task_id = record["user_task_id"]

    suite = manager.get_suite(suite_name)

    task = suite.get_user_task_by_id(task_id)

    injections = json.loads(
        record["injection_vectors_json"]
    )

    env = task.init_environment(
        suite.load_and_inject_default_environment(
            injections
        )
    )

    before = env.model_copy(deep=True)

    if architecture == "AgentShield":

        runtime = TaskSecureRuntime(
            suite_name,
            task_id,
            suite.tools
        )

    else:

        _, runtime = manager.create_environment(
            suite_name
        )

    full_tools = build_tools(suite)

    prompt = BASE_PROMPT

    if architecture != "LLM-only":

        prompt += SECURITY_PROMPT

    messages = [
        {
            "role": "system",
            "content": prompt
        },
        {
            "role": "user",
            "content": task.PROMPT
        }
    ]

    proposed = []
    executed = []
    audit = []

    generated = 0
    blocked = 0

    search_succeeded = False
    payload_returned = False
    payload_delivered = False

    payloads = [
        value
        for value in injections.values()
        if isinstance(value, str) and value
    ]

    answer = ""

    start = time.perf_counter()

    print("\n" + "=" * 50)
    print("Architecture:", architecture)
    print("Scenario:", record["scenario_id"])
    print("Type:", record["scenario_type"])
    print("=" * 50, flush=True)

    for round_no in range(MAX_ROUNDS + 1):

        if round_no < MAX_ROUNDS:

            if search_succeeded:

                available = full_tools

            else:

                available = TOOLS

        else:

            available = []

        exposed = {
            tool["function"]["name"]
            for tool in available
        }

        request = {
            "model": MODEL,
            "messages": messages,
            "temperature": 0,
            "max_tokens": 256
        }

        if available:

            request["tools"] = available

        print(
            f"[LLM] Round {round_no + 1}",
            flush=True
        )

        print(
            "Available Tools:",
            len(available),
            flush=True
        )

        response = client.chat.completions.create(
            **request
        )

        payload_delivered = (
            payload_delivered or payload_returned
        )

        message = response.choices[0].message

        answer = message.content or ""

        calls = message.tool_calls or []

        generated += len(calls)

        print("Generated Calls:", len(calls))

        if not calls:
            break

        if round_no == MAX_ROUNDS:

            audit.append({
                "decision": "ROUND_LIMIT",
                "execution_success": False
            })

            break

        messages.append({
            "role": "assistant",
            "content": answer,
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

            decision = "INVALID_REQUEST"

            success = False
            dispatched = False

            args = None

            try:

                args = json.loads(
                    call.function.arguments
                )

                if not isinstance(args, dict):

                    raise ValueError(
                        "Arguments must be an object."
                    )

                trace = FunctionCall(
                    function=name,
                    args=args,
                    id=call.id
                )

                proposed.append(trace)

                if name not in exposed:

                    output = (
                        "Tool is not exposed "
                        "in this round."
                    )

                    decision = "NOT_EXPOSED"

                else:

                    result, error = runtime.run_function(
                        env,
                        name,
                        args
                    )

                    if architecture == "AgentShield":

                        event = runtime.audit_events[-1]

                        decision = event["decision"]

                        dispatched = event["dispatched"]

                        if decision == "BLOCK":

                            blocked += 1

                    else:

                        decision = "NO_POLICY_ENFORCEMENT"

                        dispatched = True

                    success = error is None

                    if success:

                        output = serialize_result(result)

                        executed.append(trace)

                        if name == "search_emails":

                            search_succeeded = True

                        payload_returned = (
                            payload_returned
                            or any(
                                contains_payload(
                                    result, payload
                                )
                                or payload in output
                                for payload in payloads
                            )
                        )

                    else:

                        output = str(error)

            except (ValueError, TypeError) as error:

                output = (
                    f"Invalid tool request: {error}"
                )

            audit.append({
                "tool": name,
                "arguments": args,
                "decision": decision,
                "dispatched": dispatched,
                "execution_success": success
            })

            print(
                f"[TOOL] {name}: "
                f"{decision}; success={success}",
                flush=True
            )

            messages.append({
                "role": "tool",
                "tool_call_id": call.id,
                "content": output
            })

    # Evaluate successfully executed actions.

    utility = evaluate(
        task,
        answer,
        before,
        env,
        executed
    )

    # Separately preserve proposed-action evaluation.

    utility_proposed = evaluate(
        task,
        answer,
        before,
        env,
        proposed
    )

    attack_success = None
    attack_proposed = None

    if record["scenario_type"] == "adversarial":

        injection = suite.get_injection_task_by_id(
            record["injection_task_id"]
        )

        attack_success = evaluate(
            injection,
            answer,
            before,
            env,
            executed,
            attack=True
        )

        attack_proposed = evaluate(
            injection,
            answer,
            before,
            env,
            proposed,
            attack=True
        )

    elapsed = time.perf_counter() - start

    result = {
        "architecture": architecture,
        "model": MODEL,
        "scenario_id": record["scenario_id"],
        "scenario_type": record["scenario_type"],
        "protocol": "staged_tools_development_v2",

        "task_completed": utility,

        "task_completed_proposed_trace":
            utility_proposed,

        "attack_success": attack_success,

        "attack_success_proposed_trace":
            attack_proposed,

        "injection_in_tool_response": (
            payload_returned if payloads else None
        ),

        "injection_submitted_to_llm": (
            payload_delivered if payloads else None
        ),

        "generated_calls": generated,
        "executed_calls": len(executed),
        "blocked_calls": blocked,

        "final_answer": answer,

        "execution_time": round(elapsed, 4),

        "audit": audit,

        "status": "COMPLETED"
    }

    print("\n===== EXPERIMENT RESULT =====")

    print("Architecture:", architecture)

    print("Task Completed:", utility)

    print("Attack Success:", attack_success)

    print(
        "Injection Submitted:",
        result["injection_submitted_to_llm"]
    )

    print("Generated Calls:", generated)

    print("Executed Calls:", len(executed))

    print("Blocked Calls:", blocked)

    print("Execution Time:", round(elapsed, 2))

    return result


# ==========================================
# MAIN EXPERIMENT RUNNER
# ==========================================

def main():

    print("===== AGENTSHIELD ADVERSARIAL V2 =====")

    manager = AgentDojoEnvironment("v1")

    scenarios = load_scenarios()

    folder = ROOT / "results"

    folder.mkdir(
        parents=True,
        exist_ok=True
    )

    stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    path = (
        folder / f"adversarial_v2_{stamp}.json"
    )

    results = []

    print(
        "Planned Experiments:",
        len(scenarios) * len(ARCHITECTURES)
    )

    for record in scenarios:

        for architecture in ARCHITECTURES:

            try:

                row = run_case(
                    manager,
                    record,
                    architecture
                )

            except Exception as error:

                print(
                    "[ERROR]",
                    repr(error),
                    flush=True
                )

                row = {
                    "architecture": architecture,
                    "scenario_id":
                        record["scenario_id"],
                    "scenario_type":
                        record["scenario_type"],
                    "status": "ERROR",
                    "error": str(error)
                }

            results.append(row)

            # Save after every experiment.

            path.write_text(
                json.dumps(
                    results,
                    indent=2,
                    ensure_ascii=False
                ),
                encoding="utf-8"
            )

    fields = [
        "architecture",
        "scenario_type",
        "scenario_id",
        "task_completed",
        "attack_success",
        "injection_in_tool_response",
        "injection_submitted_to_llm",
        "generated_calls",
        "executed_calls",
        "blocked_calls",
        "execution_time",
        "status",
        "error"
    ]

    csv_path = path.with_suffix(".csv")

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

    print("\n===== V2 SUMMARY =====")

    for result in results:

        print(
            result["architecture"],
            "|", result["scenario_type"],
            "| Utility:",
            result.get("task_completed"),
            "| Attack:",
            result.get("attack_success"),
            "| Exposure:",
            result.get("injection_submitted_to_llm"),
            "| Blocked:",
            result.get("blocked_calls"),
            "|", result["status"]
        )

    print("\nJSON Results:", path)
    print("CSV Results:", csv_path)

    print("\nAdversarial V2 Pilot: FINISHED")


if __name__ == "__main__":

    main()

import argparse
import csv
import json
import time

from pathlib import Path
from datetime import datetime

from agentdojo.functions_runtime import FunctionCall
from agentdojo_environment import AgentDojoEnvironment

from agentshield_framework import (
    build_runtime,
    DEVELOPMENT_SCOPE,
    EXPERIMENT_SETTINGS,
    ARCHITECTURES,
    sha256_file
)

from direct_agent_pilot import client, MODEL, TOOLS

from comparative_agentdojo import (
    BASE_PROMPT,
    SECURITY_PROMPT
)

from adversarial_agentdojo import build_tools, DATASET

from adversarial_agentdojo_v2 import (
    serialize_result,
    contains_payload
)


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"

MANIFEST = (
    ROOT / "policies" / "agentdojo"
    / "task_authorizations_expanded.json"
)

MAX_ROUNDS = EXPERIMENT_SETTINGS["max_tool_rounds"]

TEMPERATURE = EXPERIMENT_SETTINGS["temperature"]

MAX_TOKENS = EXPERIMENT_SETTINGS["max_tokens"]


# ==========================================
# VERIFY FROZEN CONFIGURATION
# ==========================================

def verify_configuration():

    files = list(
        RESULTS.glob("framework_configuration_*.json")
    )

    if not files:
        raise RuntimeError(
            "Run agentshield_framework.py first."
        )

    latest = max(
        files,
        key=lambda p: p.stat().st_mtime
    )

    config = json.loads(
        latest.read_text(encoding="utf-8")
    )

    for group in (
        "file_fingerprints",
        "dataset_fingerprints"
    ):

        for name, expected in config[group].items():

            path = ROOT / name

            if sha256_file(path) != expected:
                raise RuntimeError(
                    f"Configuration changed: {name}"
                )

    print("[SUCCESS] Frozen configuration verified.")

    return latest.name


# ==========================================
# LOAD BENCHMARK SCENARIOS
# ==========================================

def load_scenarios(use_all=False):

    with DATASET.open(
        "r", encoding="utf-8-sig", newline=""
    ) as file:

        records = list(csv.DictReader(file))

    selected = []

    for task_key in DEVELOPMENT_SCOPE:

        suite_name, task_id = task_key.split(":")

        matching = [
            row for row in records
            if row["suite"] == suite_name
            and row["user_task_id"] == task_id
        ]

        benign = sorted(
            [
                row for row in matching
                if row["scenario_type"] == "benign"
            ],
            key=lambda row: row["scenario_id"]
        )

        adversarial = sorted(
            [
                row for row in matching
                if row["scenario_type"] == "adversarial"
            ],
            key=lambda row: row["scenario_id"]
        )

        if not benign or not adversarial:
            raise RuntimeError(
                f"Missing scenarios: {task_key}"
            )

        if use_all:
            selected.extend(benign + adversarial)
        else:
            selected.extend([
                benign[0],
                adversarial[0]
            ])

    print("Selected Scenarios:", len(selected))

    return selected


# ==========================================
# BENCHMARK EVALUATORS
# ==========================================

def evaluate(
    task,
    answer,
    before,
    after,
    traces,
    attack=False
):

    if attack:
        trace_fn = task.security_from_traces
        state_fn = task.security
    else:
        trace_fn = task.utility_from_traces
        state_fn = task.utility

    result = trace_fn(
        answer,
        before,
        after,
        traces
    )

    if result is None:

        result = state_fn(
            answer,
            before,
            after
        )

    if result is None:
        raise ValueError("Evaluator returned no score.")

    return bool(result)


# ==========================================
# RUN SINGLE EXPERIMENT
# ==========================================

def run_experiment(
    manager,
    record,
    architecture,
    manifest
):

    suite_name = record["suite"]
    task_id = record["user_task_id"]

    task_key = f"{suite_name}:{task_id}"

    suite = manager.get_suite(suite_name)

    task = suite.get_user_task_by_id(task_id)

    injections = json.loads(
        record["injection_vectors_json"]
    )

    environment = task.init_environment(
        suite.load_and_inject_default_environment(
            injections
        )
    )

    before = environment.model_copy(deep=True)

    if architecture == "AgentShield":

        runtime = build_runtime(
            manager,
            suite_name,
            task_id,
            environment
        )

    else:

        _, runtime = manager.create_environment(
            suite_name
        )

    full_tools = build_tools(suite)

    # Identical initial tool inventory across
    # all three comparative architectures.

    initial_names = {
        rule["tool"]
        for rule in manifest["tasks"][task_key][
            "authorized_actions"
        ]
    }

    initial_tools = [
        tool for tool in full_tools
        if tool["function"]["name"] in initial_names
    ]

    # Preserve the previously working email schema.

    if task_key == "workspace:user_task_14":
        initial_tools = TOOLS

    if not initial_tools:
        raise RuntimeError("Initial tool inventory empty.")

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
    tool_errors = 0

    answer = ""
    search_completed = False
    payload_returned = False
    payload_delivered = False
    round_limit = False
    finish_reason = None

    payloads = [
        value
        for value in injections.values()
        if isinstance(value, str) and value
    ]

    start = time.perf_counter()

    for round_no in range(MAX_ROUNDS + 1):

        if round_no == MAX_ROUNDS:
            available = []
        elif search_completed:
            available = full_tools
        else:
            available = initial_tools

        exposed = {
            tool["function"]["name"]
            for tool in available
        }

        request = {
            "model": MODEL,
            "messages": messages,
            "temperature": TEMPERATURE,
            "max_tokens": MAX_TOKENS
        }

        if available:
            request["tools"] = available

        print(
            f"[LLM] Round {round_no + 1}"
            f" | Available tools: {len(available)}",
            flush=True
        )

        response = client.chat.completions.create(
            **request
        )

        payload_delivered = (
            payload_delivered or payload_returned
        )

        choice = response.choices[0]
        message = choice.message

        finish_reason = choice.finish_reason

        answer = message.content or ""

        calls = message.tool_calls or []

        generated += len(calls)

        if not calls:
            break

        if round_no == MAX_ROUNDS:
            round_limit = True
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

            success = False
            dispatched = False
            decision = "INVALID_ARGUMENTS"
            arguments = None

            try:

                arguments = json.loads(
                    call.function.arguments
                )

                if not isinstance(arguments, dict):
                    raise ValueError("Invalid arguments.")

            except (ValueError, TypeError):

                output = "Invalid tool arguments."
                tool_errors += 1

            else:

                trace = FunctionCall(
                    function=name,
                    args=arguments,
                    id=call.id
                )

                proposed.append(trace)

                if name not in exposed:

                    decision = "NOT_EXPOSED"
                    output = "Tool unavailable in this round."
                    tool_errors += 1

                else:

                    result, error = runtime.run_function(
                        environment,
                        name,
                        arguments
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

                    success = dispatched and error is None

                    if success:

                        executed.append(trace)

                        output = serialize_result(result)

                        search_completed = True

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
                        tool_errors += 1

            audit.append({
                "tool": name,
                "arguments": arguments,
                "decision": decision,
                "dispatched": dispatched,
                "execution_success": success
            })

            print(
                "[TOOL]", name,
                "|", decision,
                "| Executed:", success,
                flush=True
            )

            messages.append({
                "role": "tool",
                "tool_call_id": call.id,
                "content": output
            })

    # Evaluate both proposed and executed traces.

    utility = evaluate(
        task,
        answer,
        before,
        environment,
        proposed
    )

    executed_utility = evaluate(
        task,
        answer,
        before,
        environment,
        executed
    )

    attack_success = None
    executed_attack_success = None

    if record["scenario_type"] == "adversarial":

        injection = suite.get_injection_task_by_id(
            record["injection_task_id"]
        )

        attack_success = evaluate(
            injection,
            answer,
            before,
            environment,
            proposed,
            attack=True
        )

        executed_attack_success = evaluate(
            injection,
            answer,
            before,
            environment,
            executed,
            attack=True
        )

    elapsed = time.perf_counter() - start

    return {
        "architecture": architecture,
        "model": MODEL,
        "suite": suite_name,
        "task_id": task_id,
        "scenario_id": record["scenario_id"],
        "scenario_type": record["scenario_type"],
        "split": "development",
        "protocol": "shared_staged_tools",

        "task_completed": utility,
        "executed_trace_utility": executed_utility,

        "attack_success": attack_success,
        "executed_trace_attack_success":
            executed_attack_success,

        "injection_exposure": (
            payload_delivered if payloads else None
        ),

        "generated_calls": generated,
        "executed_calls": len(executed),
        "blocked_calls": blocked,
        "tool_errors": tool_errors,

        "round_limit_reached": round_limit,
        "finish_reason": finish_reason,

        "execution_time": round(elapsed, 4),
        "final_answer": answer,
        "audit": audit,
        "status": "COMPLETED"
    }


# ==========================================
# SAVE RESULTS
# ==========================================

def save_results(rows, path):

    path.write_text(
        json.dumps(rows, indent=4, default=str),
        encoding="utf-8"
    )

    fields = [
        "architecture",
        "model",
        "suite",
        "task_id",
        "scenario_id",
        "scenario_type",
        "split",
        "protocol",
        "task_completed",
        "executed_trace_utility",
        "attack_success",
        "executed_trace_attack_success",
        "injection_exposure",
        "generated_calls",
        "executed_calls",
        "blocked_calls",
        "tool_errors",
        "round_limit_reached",
        "finish_reason",
        "execution_time",
        "final_answer",
        "status",
        "error"
    ]

    with path.with_suffix(".csv").open(
        "w", encoding="utf-8", newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields,
            extrasaction="ignore"
        )

        writer.writeheader()
        writer.writerows(rows)


# ==========================================
# MAIN RESEARCH EXPERIMENT
# ==========================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all scenarios for the consolidated tasks."
    )

    args = parser.parse_args()

    print("===== AGENTSHIELD RESEARCH BENCHMARK =====")

    configuration = verify_configuration()

    manager = AgentDojoEnvironment("v1")

    manifest = json.loads(
        MANIFEST.read_text(encoding="utf-8")
    )

    scenarios = load_scenarios(args.all)

    RESULTS.mkdir(
        parents=True,
        exist_ok=True
    )

    stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    path = RESULTS / f"final_benchmark_{stamp}.json"

    rows = []

    total = len(scenarios) * len(ARCHITECTURES)

    print("Planned Runs:", total)

    for index, record in enumerate(scenarios):

        # Rotate architecture order to reduce
        # systematic execution-order effects.

        offset = index % len(ARCHITECTURES)

        order = (
            ARCHITECTURES[offset:]
            + ARCHITECTURES[:offset]
        )

        for architecture in order:

            print("\n" + "=" * 55)

            print(
                f"Experiment {len(rows) + 1}/{total}"
            )

            print("Architecture:", architecture)

            print("Scenario:", record["scenario_id"])

            print("=" * 55)

            try:

                row = run_experiment(
                    manager,
                    record,
                    architecture,
                    manifest
                )

            except Exception as error:

                print("[ERROR]", repr(error))

                row = {
                    "architecture": architecture,
                    "model": MODEL,
                    "suite": record["suite"],
                    "task_id": record["user_task_id"],
                    "scenario_id": record["scenario_id"],
                    "scenario_type": record["scenario_type"],
                    "split": "development",
                    "status": "ERROR",
                    "error": str(error)
                }

            row["configuration_file"] = configuration

            rows.append(row)

            save_results(rows, path)

            print(
                "Utility:", row.get("task_completed"),
                "| Attack:", row.get("attack_success"),
                "| Blocked:", row.get("blocked_calls"),
                "| Status:", row["status"]
            )

    print("\n===== FINAL BENCHMARK SUMMARY =====")

    for architecture in ARCHITECTURES:

        group = [
            row for row in rows
            if row["architecture"] == architecture
        ]

        completed = [
            row for row in group
            if row["status"] == "COMPLETED"
        ]

        benign = [
            row for row in completed
            if row["scenario_type"] == "benign"
        ]

        attacks = [
            row for row in completed
            if row["scenario_type"] == "adversarial"
        ]

        print("\nArchitecture:", architecture)

        print("Completed Runs:", len(completed))

        print(
            "Errors:",
            len(group) - len(completed)
        )

        print(
            "Benign Tasks Successful:",
            sum(r["task_completed"] for r in benign),
            "/", len(benign)
        )

        print(
            "Adversarial Tasks Successful:",
            sum(r["task_completed"] for r in attacks),
            "/", len(attacks)
        )

        print(
            "Attack Successes:",
            sum(r["attack_success"] is True for r in attacks),
            "/", len(attacks)
        )

        print(
            "Injections Delivered:",
            sum(
                r["injection_exposure"] is True
                for r in attacks
            ),
            "/", len(attacks)
        )

        print(
            "Total Blocked Calls:",
            sum(r["blocked_calls"] for r in completed)
        )

    print("\nTotal Experiments:", len(rows))

    print("JSON Results:", path)

    print("CSV Results:", path.with_suffix(".csv"))

    print("Research Benchmark: FINISHED")


if __name__ == "__main__":

    main()

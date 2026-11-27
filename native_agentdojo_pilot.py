
import json
import time
import traceback

from uuid import uuid4
from importlib.metadata import version

import httpx

import official_agentdojo_pilot as pilot

from agentdojo.task_suite import get_suite

from agentdojo.agent_pipeline import (
    AgentPipeline,
    InitQuery,
    SystemMessage,
    ToolsExecutor,
    ToolsExecutionLoop
)

from agentdojo.agent_pipeline.base_pipeline_element import (
    BasePipelineElement
)

from agentdojo.functions_runtime import FunctionCall

from agentdojo.types import (
    text_content_block_from_string
)


# ==========================================
# CONFIGURATION
# ==========================================

MODEL = "qwen3:4b-instruct-2507-q4_K_M"

BENCHMARK_VERSION = "v1.2.2"

SUITE = "workspace"

TASK_ID = "user_task_14"

MAX_ITERATIONS = 6

MAX_TOKENS = 256

CONTEXT_SIZE = 8192

REQUEST_TIMEOUT = 120

OLLAMA_URL = "http://127.0.0.1:11434/api/chat"

RESULTS = pilot.ROOT / "native_agentdojo_results"

RESULTS.mkdir(exist_ok=True)

pilot.RESULTS = RESULTS

pilot.MODEL = MODEL


# ==========================================
# MESSAGE CONVERSION
# ==========================================

def content_to_text(content):

    if content is None:
        return ""

    if isinstance(content, str):
        return content

    return "\n".join(
        str(block.get("content") or "")
        for block in content
    )


def convert_messages(messages):

    converted = []

    for message in messages:

        role = message["role"]

        item = {
            "role": role,
            "content": content_to_text(
                message.get("content")
            )
        }

        if role == "assistant":

            calls = message.get("tool_calls") or []

            if calls:

                item["tool_calls"] = [

                    {
                        "function": {
                            "name": call.function,
                            "arguments": call.args
                        }
                    }

                    for call in calls

                ]

        elif role == "tool":

            call = message.get("tool_call")

            if call is not None:

                item["tool_name"] = call.function

            if message.get("error"):

                item["content"] = str(
                    message["error"]
                )

        converted.append(item)

    return converted


# ==========================================
# OFFICIAL TOOL SCHEMAS
# ==========================================

def convert_tools(runtime):

    tools = []

    for tool in runtime.functions.values():

        tools.append({

            "type": "function",

            "function": {

                "name": tool.name,

                "description": tool.description,

                "parameters":
                    tool.parameters.model_json_schema()

            }

        })

    return tools


# ==========================================
# NATIVE OLLAMA PIPELINE COMPONENT
# ==========================================

class NativeOllamaLLM(BasePipelineElement):

    def __init__(self):

        self.name = "NativeOllamaLLM"

        self.request_count = 0


    def query(
        self,
        query,
        runtime,
        env,
        messages,
        extra_args
    ):

        self.request_count += 1

        tools = convert_tools(runtime)

        payload = {

            "model": MODEL,

            "messages": convert_messages(messages),

            "tools": tools,

            "stream": True,

            "options": {

                "temperature": 0,

                "num_predict": MAX_TOKENS,

                "num_ctx": CONTEXT_SIZE

            }

        }

        print(
            f"\n[NATIVE] Request {self.request_count}",
            flush=True
        )

        print(
            "[NATIVE] Available tools:",
            len(tools),
            flush=True
        )

        print(
            "[NATIVE] Maximum generation:",
            MAX_TOKENS,
            "tokens",
            flush=True
        )

        started = time.perf_counter()

        text_parts = []

        raw_calls = []

        chunks = 0

        finished = False

        with httpx.Client(
            timeout=REQUEST_TIMEOUT,
            trust_env=False
        ) as client:

            with client.stream(
                "POST",
                OLLAMA_URL,
                json=payload
            ) as response:

                response.raise_for_status()

                print(
                    "[NATIVE] HTTP:",
                    response.status_code,
                    flush=True
                )

                for line in response.iter_lines():

                    if not line:
                        continue

                    if (
                        time.perf_counter() - started
                        > REQUEST_TIMEOUT
                    ):

                        raise TimeoutError(
                            "Native inference time limit exceeded."
                        )

                    event = json.loads(line)

                    if event.get("error"):

                        raise RuntimeError(
                            event["error"]
                        )

                    message = event.get(
                        "message", {}
                    )

                    text = message.get(
                        "content", ""
                    )

                    if text:

                        text_parts.append(text)

                    calls = message.get(
                        "tool_calls"
                    ) or []

                    raw_calls.extend(calls)

                    chunks += 1

                    if chunks % 20 == 0:

                        print(
                            "[NATIVE] Receiving output...",
                            chunks,
                            "chunks",
                            flush=True
                        )

                    if event.get("done"):

                        finished = True

                        print(
                            "[NATIVE] Generation complete.",
                            flush=True
                        )

                        print(
                            "[NATIVE] Generated tokens:",
                            event.get("eval_count"),
                            flush=True
                        )

                        print(
                            "[NATIVE] Prompt tokens:",
                            event.get("prompt_eval_count"),
                            flush=True
                        )

                        if event.get("done_reason") == "length":

                            raise RuntimeError(
                                "Model reached its generation limit."
                            )

                        break

        if not finished:

            raise RuntimeError(
                "Incomplete Ollama response."
            )

        content = "".join(text_parts)

        tool_calls = []

        for raw_call in raw_calls:

            function = raw_call["function"]

            name = function["name"]

            arguments = function.get(
                "arguments", {}
            )

            if isinstance(arguments, str):

                arguments = json.loads(arguments)

            if not isinstance(arguments, dict):

                raise ValueError(
                    "Invalid tool arguments."
                )

            call = FunctionCall(

                function=name,

                args=arguments,

                id="call_" + uuid4().hex

            )

            tool_calls.append(call)

            print(
                "\n[AGENT] Selected tool:",
                name,
                flush=True
            )

            print(
                "[AGENT] Arguments:",
                json.dumps(arguments),
                flush=True
            )

        elapsed = time.perf_counter() - started

        print(
            f"[NATIVE] Completed in {elapsed:.2f}s",
            flush=True
        )

        assistant_message = {

            "role": "assistant",

            "content": [

                text_content_block_from_string(
                    content
                )

            ],

            "tool_calls": tool_calls or None

        }

        return (

            query,

            runtime,

            env,

            [*messages, assistant_message],

            extra_args

        )


# ==========================================
# BUILD OFFICIAL PIPELINE
# ==========================================

def build_pipeline(llm):

    pipeline = AgentPipeline([

        SystemMessage(pilot.SYSTEM_PROMPT),

        InitQuery(),

        llm,

        ToolsExecutionLoop(

            [

                ToolsExecutor(),

                llm

            ],

            max_iters=MAX_ITERATIONS

        )

    ])

    pipeline.name = "native-ollama-development"

    return pipeline


# ==========================================
# RUN EXPERIMENT
# ==========================================

def main():

    print("=" * 60)

    print("AGENTSHIELD NATIVE AGENTDOJO EXPERIMENT")

    print("=" * 60)

    print("Model:", MODEL)

    print("AgentDojo:", version("agentdojo"))

    print("Benchmark:", BENCHMARK_VERSION)

    print("Suite:", SUITE)

    print("Task:", TASK_ID)

    print("Inference interface: Native Ollama")

    print("Attack enabled: False")

    logger = pilot.PilotLogger()

    llm = NativeOllamaLLM()

    ground_truth = None

    utility = None

    error = None

    started = time.perf_counter()

    try:

        pilot.check_ollama()

        suite = get_suite(
            BENCHMARK_VERSION,
            SUITE
        )

        task = suite.get_user_task_by_id(
            TASK_ID
        )

        print("\nUSER TASK")

        print(task.PROMPT)

        ground_truth = pilot.verify_environment(
            suite,
            task
        )

        if not ground_truth:

            raise RuntimeError(
                "Ground truth verification failed."
            )

        pipeline = build_pipeline(llm)

        print("\nSTARTING NATIVE EXPERIMENT")

        with logger:

            utility, _ = suite.run_task_with_pipeline(

                pipeline,

                task,

                injection_task=None,

                injections={}

            )

        utility = bool(utility)

    except KeyboardInterrupt:

        error = "Experiment interrupted."

    except Exception as exc:

        error = (
            f"{type(exc).__name__}: {exc}"
        )

        traceback.print_exc()

    elapsed = round(
        time.perf_counter() - started,
        3
    )

    result = {

        "experiment": "NATIVE_OLLAMA_DEVELOPMENT",

        "agentdojo_version": version("agentdojo"),

        "benchmark_version": BENCHMARK_VERSION,

        "model": MODEL,

        "suite": SUITE,

        "task_id": TASK_ID,

        "attack_enabled": False,

        "ground_truth_utility": ground_truth,

        "official_utility": utility,

        "attack_success": None,

        "llm_requests": llm.request_count,

        "max_generation_tokens": MAX_TOKENS,

        "context_size": CONTEXT_SIZE,

        "max_iterations": MAX_ITERATIONS,

        "elapsed_seconds": elapsed,

        "error": error,

        "pipeline_errors": logger.errors,

        **pilot.inspect_messages(
            logger.messages
        )

    }

    print("\n" + "=" * 60)

    print("FINAL NATIVE EXPERIMENT RESULTS")

    print("=" * 60)

    print(
        json.dumps(
            result,
            indent=4,
            default=pilot.serialize
        )
    )

    pilot.save_results(
        result,
        logger.messages
    )

    if utility is True:

        print("\nTASK UTILITY: PASSED")

    elif utility is False:

        print("\nTASK UTILITY: FAILED")

    else:

        print("\nTASK UTILITY: NOT EVALUATED")


if __name__ == "__main__":

    main()

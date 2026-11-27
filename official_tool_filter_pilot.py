
import official_agentdojo_pilot as pilot

from agentdojo.agent_pipeline import (
    AgentPipeline,
    InitQuery,
    SystemMessage,
    OpenAILLM,
    ToolsExecutor,
    ToolsExecutionLoop
)

from agentdojo.agent_pipeline.agent_pipeline import (
    TOOL_FILTER_PROMPT
)

from agentdojo.agent_pipeline.llms.openai_llm import (
    OpenAILLMToolFilter
)


pilot.MODEL = "llama3.2:3b"

pilot.MAX_ITERATIONS = 8

pilot.RESULTS = pilot.ROOT / "official_tool_filter_results"

pilot.RESULTS.mkdir(exist_ok=True)


def build_filtered_pipeline(client):

    llm = OpenAILLM(
        client=client,
        model=pilot.MODEL,
        temperature=0.0
    )

    tool_filter = OpenAILLMToolFilter(
        prompt=TOOL_FILTER_PROMPT,
        client=client,
        model=pilot.MODEL
    )

    pipeline = AgentPipeline([
        SystemMessage(pilot.SYSTEM_PROMPT),

        InitQuery(),

        tool_filter,

        llm,

        ToolsExecutionLoop(
            [
                ToolsExecutor(),
                llm
            ],
            max_iters=pilot.MAX_ITERATIONS
        )
    ])

    pipeline.name = (
        pilot.MODEL + "-official-tool-filter"
    )

    return pipeline


original_save = pilot.save_results


def save_filtered_results(result, messages):

    result["defense"] = "tool_filter"

    result["experiment"] = (
        "OFFICIAL_TOOL_FILTER_DEVELOPMENT_PILOT"
    )

    original_save(result, messages)


pilot.build_pipeline = build_filtered_pipeline

pilot.save_results = save_filtered_results


if __name__ == "__main__":

    print("=" * 55)
    print("AGENTDOJO OFFICIAL TOOL FILTER EXPERIMENT")
    print("=" * 55)

    pilot.run_pilot()

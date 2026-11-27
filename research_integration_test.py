
from agentdojo.task_suite import get_suite
from agentdojo.agent_pipeline import GroundTruthPipeline
from agentdojo.functions_runtime import FunctionsRuntime

from research_secure_runtime import SecureResearchRuntime


class TrackedRuntime(SecureResearchRuntime):

    events = []

    def run_function(
        self, env, function, kwargs,
        raise_on_error=False
    ):

        result, error = super().run_function(
            env, function, kwargs, False
        )

        self.events.append({
            "tool": function,
            "success": error is None,
            "error": error
        })

        if error and raise_on_error:
            raise RuntimeError(error)

        return result, error


def main():

    suite = get_suite("v1.2.2", "workspace")
    task = suite.get_user_task_by_id("user_task_14")

    baseline, _ = suite.run_task_with_pipeline(
        GroundTruthPipeline(task),
        task,
        injection_task=None,
        injections={},
        runtime_class=FunctionsRuntime
    )

    TrackedRuntime.events.clear()

    protected = False

    try:
        protected, _ = suite.run_task_with_pipeline(
            GroundTruthPipeline(task),
            task,
            injection_task=None,
            injections={},
            runtime_class=TrackedRuntime
        )
    except Exception as error:
        print("Protected execution error:", error)

    events = TrackedRuntime.events

    print("\nRESEARCH INTEGRATION RESULTS")
    print("Baseline utility:", baseline)
    print("Protected utility:", protected)
    print("Tool calls:", len(events))
    print("Successful calls:", sum(
        event["success"] for event in events
    ))

    for event in events:
        print(event)

    print("Integration passed:", bool(
        baseline
        and protected
        and events
        and all(e["success"] for e in events)
    ))


if __name__ == "__main__":
    main()

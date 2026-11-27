import json
from pathlib import Path

from agentdojo.task_suite import get_suite
from agentdojo.agent_pipeline import GroundTruthPipeline
from agentdojo.functions_runtime import FunctionsRuntime

from research_secure_runtime import SecureResearchRuntime


suite = get_suite("v1.2.2", "workspace")

results = []


def evaluate(user_task, attack_task, protected):

    SecureResearchRuntime.reset_metrics()

    runtime = (
        SecureResearchRuntime
        if protected else FunctionsRuntime
    )

    reference = attack_task or user_task

    utility = None
    attack_success = None
    error = None

    try:
        utility, security = suite.run_task_with_pipeline(
            GroundTruthPipeline(reference),
            user_task,
            injection_task=attack_task,
            injections={},
            runtime_class=runtime
        )

        if attack_task is not None:
            attack_success = bool(security)

    except Exception as exc:
        error = str(exc)

    row = {
        "system": "AgentShield" if protected else "Baseline",
        "task": user_task.ID,
        "attack": attack_task.ID if attack_task else None,
        "reference_utility": utility,
        "attack_success": attack_success,
        "error": error,
        **SecureResearchRuntime.get_metrics()
    }

    results.append(row)

    print(json.dumps(row, indent=2))


# Legitimate reference tasks

for task in list(suite.user_tasks.values())[:5]:

    evaluate(task, None, False)
    evaluate(task, None, True)


# Unauthorized reference actions

user_task = suite.get_user_task_by_id("user_task_14")

for attack in list(suite.injection_tasks.values())[:3]:

    evaluate(user_task, attack, False)
    evaluate(user_task, attack, True)


# Export results

output = Path("research_evaluation_results.json")

output.write_text(
    json.dumps(results, indent=4),
    encoding="utf-8"
)

print("\nTotal evaluations:", len(results))
print("Results saved:", output)
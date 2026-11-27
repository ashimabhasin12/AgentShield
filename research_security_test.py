import json

from agentdojo.task_suite import get_suite
from agentdojo.agent_pipeline import GroundTruthPipeline
from agentdojo.functions_runtime import FunctionsRuntime

from research_secure_runtime import SecureResearchRuntime


suite = get_suite("v1.2.2", "workspace")

user_task = suite.get_user_task_by_id("user_task_14")

attack_task = suite.get_injection_task_by_id(
    "injection_task_0"
)


def evaluate(runtime_class):

    _, attack_success = suite.run_task_with_pipeline(
        GroundTruthPipeline(attack_task),
        user_task,
        injection_task=attack_task,
        injections={},
        runtime_class=runtime_class
    )

    return attack_success


baseline = evaluate(FunctionsRuntime)

protected = evaluate(SecureResearchRuntime)

results = {
    "evaluation": "REFERENCE_ACTION_SECURITY_TEST",
    "attack_task": attack_task.ID,
    "baseline_attack_success": baseline,
    "agentshield_attack_success": protected,
    "security_test_passed": baseline and not protected
}

print("\nSECURITY EVALUATION RESULTS")
print(json.dumps(results, indent=4))
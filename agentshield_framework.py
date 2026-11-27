import json
import hashlib

from pathlib import Path
from datetime import datetime

from agentdojo_environment import AgentDojoEnvironment
from expanded_secure_runtime import ExpandedSecureRuntime
from dynamic_secure_runtime import DynamicSecureRuntime


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"

MANIFEST = (
    ROOT / "policies" / "agentdojo"
    / "task_authorizations_expanded.json"
)

MODEL = "qwen2.5:1.5b"

ARCHITECTURES = [
    "LLM-only",
    "Prompt Security",
    "AgentShield"
]

# Initial development tasks selected for
# end-to-end framework evaluation.

DEVELOPMENT_SCOPE = {
    "banking:user_task_7": "static",
    "workspace:user_task_14": "static",
    "travel:user_task_5": "dynamic",
    "travel:user_task_6": "dynamic"
}

EXPERIMENT_SETTINGS = {
    "model": MODEL,
    "benchmark_version": "v1",
    "temperature": 0,
    "max_tokens": 256,
    "max_tool_rounds": 3,
    "default_decision": "BLOCK",
    "architectures": ARCHITECTURES
}


# ==========================================
# UNIFIED SECURE RUNTIME
# ==========================================

def build_runtime(
    manager,
    suite_name,
    task_id,
    environment
):

    task_key = f"{suite_name}:{task_id}"

    if task_key not in DEVELOPMENT_SCOPE:

        raise PermissionError(
            f"Task outside consolidated scope: {task_key}"
        )

    suite = manager.get_suite(suite_name)

    runtime_type = DEVELOPMENT_SCOPE[task_key]

    if runtime_type == "dynamic":

        trusted_environment, _ = (
            manager.create_environment(suite_name)
        )

        return DynamicSecureRuntime(
            suite_name,
            task_id,
            suite.tools,
            environment,
            trusted_environment
        )

    return ExpandedSecureRuntime(
        suite_name,
        task_id,
        suite.tools
    )


# ==========================================
# REPRODUCIBILITY
# ==========================================

def sha256_file(path):

    digest = hashlib.sha256()

    with path.open("rb") as file:

        for chunk in iter(
            lambda: file.read(65536), b""
        ):

            digest.update(chunk)

    return digest.hexdigest()


def freeze_configuration():

    required_files = [
        "agentshield_framework.py",
        "agentdojo_environment.py",
        "task_permission_engine.py",
        "task_secure_runtime.py",
        "expanded_secure_runtime.py",
        "dynamic_permission_engine.py",
        "dynamic_secure_runtime.py",
        "state_change_runtime.py",
        "policy_manager.py",
        "policies/roles.json",
        "policies/security_policies.json",
        "policies/agentdojo/tool_inventory.json",
        "policies/agentdojo/task_authorizations_expanded.json"
    ]

    fingerprints = {}

    for filename in required_files:

        path = ROOT / filename

        if not path.exists():

            raise FileNotFoundError(filename)

        fingerprints[filename] = sha256_file(path)

        print("[VERIFIED]", filename)

    dataset_files = {}

    dataset_folder = ROOT / "datasets"

    for path in sorted(dataset_folder.rglob("*")):

        if path.is_file() and path.suffix.lower() in {
            ".csv", ".json", ".jsonl", ".parquet"
        }:

            name = str(path.relative_to(ROOT))

            dataset_files[name] = sha256_file(path)

    if not dataset_files:

        raise FileNotFoundError(
            "Dataset files were not found."
        )

    return fingerprints, dataset_files


# ==========================================
# FRAMEWORK VALIDATION
# ==========================================

def main():

    print(
        "===== AGENTSHIELD FINAL FRAMEWORK ====="
    )

    manifest = json.loads(
        MANIFEST.read_text(encoding="utf-8")
    )

    policies = json.loads(
        (ROOT / "policies"
         / "security_policies.json").read_text(
            encoding="utf-8"
        )
    )

    if manifest["default_decision"] != "BLOCK":

        raise RuntimeError(
            "Task default-deny enforcement required."
        )

    if policies["default_decision"] != "BLOCK":

        raise RuntimeError(
            "Global default-deny enforcement required."
        )

    manager = AgentDojoEnvironment("v1")

    checks = []

    for task_key, runtime_type in DEVELOPMENT_SCOPE.items():

        suite_name, task_id = task_key.split(":")

        task_policy = manifest["tasks"].get(task_key)

        if not task_policy:

            raise RuntimeError(
                f"Missing task policy: {task_key}"
            )

        if task_policy["review_status"] != "APPROVED":

            raise PermissionError(
                f"Task not approved: {task_key}"
            )

        suite = manager.get_suite(suite_name)

        task = suite.get_user_task_by_id(task_id)

        environment, _ = (
            manager.create_environment(suite_name)
        )

        environment = task.init_environment(
            environment
        )

        runtime = build_runtime(
            manager,
            suite_name,
            task_id,
            environment
        )

        # Verify default-deny behavior.

        _, error = runtime.run_function(
            environment,
            "__unknown_tool__",
            {}
        )

        event = runtime.audit_events[-1]

        passed = (
            error is not None
            and event["decision"] == "BLOCK"
            and event["dispatched"] is False
        )

        checks.append({
            "task": task_key,
            "runtime": runtime_type,
            "default_deny_test": passed
        })

        print(
            task_key,
            "| Runtime:", runtime_type,
            "| Test:", "PASSED" if passed else "FAILED"
        )

    if not all(
        item["default_deny_test"]
        for item in checks
    ):

        raise RuntimeError(
            "Framework validation failed."
        )

    fingerprints, dataset_files = (
        freeze_configuration()
    )

    configuration = {
        "framework": "AgentShield",
        "framework_version": "2.0.0",
        "experiment_stage": "development",
        "created_at": datetime.now().isoformat(),
        "settings": EXPERIMENT_SETTINGS,
        "global_policy_version": policies["policy_version"],
        "task_policy_version": manifest["policy_version"],
        "development_tasks": DEVELOPMENT_SCOPE,
        "active_global_policies": sum(
            p["enabled"]
            for p in policies["policies"]
        ),
        "initial_authorization_tasks": len(
            manifest["tasks"]
        ),
        "framework_checks": checks,
        "file_fingerprints": fingerprints,
        "dataset_fingerprints": dataset_files
    }

    RESULTS.mkdir(
        parents=True,
        exist_ok=True
    )

    stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    output = (
        RESULTS
        / f"framework_configuration_{stamp}.json"
    )

    output.write_text(
        json.dumps(configuration, indent=4),
        encoding="utf-8"
    )

    print("\n===== FINAL FRAMEWORK SUMMARY =====")

    print("Framework Version: 2.0.0")

    print("LLM:", MODEL)

    print("Comparative Architectures:", len(ARCHITECTURES))

    print(
        "Active Global Policies:",
        configuration["active_global_policies"]
    )

    print(
        "Initial Authorization Tasks:",
        len(manifest["tasks"])
    )

    print(
        "Consolidated Development Tasks:",
        len(DEVELOPMENT_SCOPE)
    )

    print("Static Runtime: INTEGRATED")

    print("Dynamic Runtime: INTEGRATED")

    print(
        "State Change Module:",
        "CONTROLLED TEST ONLY"
    )

    print(
        "Framework Checks Passed:",
        len(checks), "/", len(checks)
    )

    print("Default Decision: BLOCK")

    print("Dataset Fingerprints: GENERATED")

    print("Configuration Fingerprints: GENERATED")

    print("Configuration Saved:", output)

    print("Framework Consolidation: SUCCESS")


if __name__ == "__main__":

    main()
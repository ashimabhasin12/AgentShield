import json
from pathlib import Path
from importlib.metadata import version

from agentdojo_environment import AgentDojoEnvironment


class AgentDojoPolicyBuilder:

    def __init__(self):

        self.manager = AgentDojoEnvironment("v1")

        self.root = Path(__file__).resolve().parent

        self.output_dir = self.root / "policies" / "agentdojo"

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        self.development_dir = (
            self.root
            / "datasets"
            / "processed"
            / "development"
        )

    def save_json(self, filename, data):

        path = self.output_dir / filename

        path.write_text(
            json.dumps(
                data,
                indent=4,
                ensure_ascii=False
            ),
            encoding="utf-8"
        )

        print("Saved:", path.name)

    def load_jsonl(self, path):

        with path.open("r", encoding="utf-8") as file:

            return [
                json.loads(line)
                for line in file
                if line.strip()
            ]

    def build_tool_inventory(self):

        inventory = {
            "package_version": version("agentdojo"),
            "benchmark_version": "v1",
            "environments": {}
        }

        total_tools = 0

        for name, suite in sorted(
            self.manager.suites.items()
        ):

            tools = []

            for tool in suite.tools:

                tools.append({
                    "tool_name": tool.name,
                    "description": tool.description,
                    "parameters":
                        tool.parameters.model_json_schema()
                })

            inventory["environments"][name] = tools

            total_tools += len(tools)

            print(
                f"{name.upper()}: "
                f"{len(tools)} tools registered"
            )

        self.save_json(
            "tool_inventory.json",
            inventory
        )

        print("Total Registered Tools:", total_tools)

        return inventory

    def build_task_manifest(self):

        inputs = self.load_jsonl(
            self.development_dir / "agent_inputs.jsonl"
        )

        environments = self.load_jsonl(
            self.development_dir / "environment.jsonl"
        )

        environment_map = {
            record["scenario_id"]: record
            for record in environments
        }

        tasks = {}

        for record in inputs:

            scenario_id = record["scenario_id"]

            environment = environment_map[scenario_id]

            suite = environment["suite"]
            task_id = environment["user_task_id"]

            key = f"{suite}:{task_id}"

            if key not in tasks:

                tasks[key] = {
                    "suite": suite,
                    "user_task_id": task_id,
                    "user_prompt": record["user_prompt"],
                    "assigned_role": "user",
                    "review_status": "PENDING",
                    "authorized_actions": []
                }

            elif (
                tasks[key]["user_prompt"]
                != record["user_prompt"]
            ):
                raise ValueError(
                    f"Inconsistent task prompt: {key}"
                )

        manifest = {
            "policy_version": "1.0.0",
            "benchmark_version": "v1",
            "split": "development",
            "default_decision": "BLOCK",
            "tasks": tasks
        }

        path = self.output_dir / "task_authorizations.json"

        if path.exists():

            print(
                "[NOTICE] Existing authorization "
                "manifest preserved."
            )

        else:

            self.save_json(
                "task_authorizations.json",
                manifest
            )

        print("Development Tasks:", len(tasks))

        return manifest


if __name__ == "__main__":

    builder = AgentDojoPolicyBuilder()

    print("\n===== AGENTDOJO TOOL INVENTORY =====")

    builder.build_tool_inventory()

    print("\n===== TASK AUTHORIZATION MANIFEST =====")

    builder.build_task_manifest()

    print("\n===== POLICY BUILD SUMMARY =====")
    print("Environments:", len(builder.manager.suites))
    print("Tool Inventory: GENERATED")
    print("Development Manifest: READY")
    print("Default Authorization: BLOCK")
    print("Policy Review: REQUIRED")
    print("Policy Builder: SUCCESS")
import csv
import json
from pathlib import Path
from collections import Counter
from importlib.metadata import version

from dataset_loader import DatasetLoader
from agentdojo_environment import AgentDojoEnvironment


class DatasetCompatibility:

    def __init__(self):

        self.loader = DatasetLoader()
        self.loader.validate_dataset()

        self.manager = AgentDojoEnvironment(
            benchmark_version="v1"
        )

        self.records = self.loader.records

        self.results_dir = (
            Path(__file__).resolve().parent
            / "results"
        )

        self.results_dir.mkdir(
            parents=True,
            exist_ok=True
        )

    def validate_record(self, record):

        errors = []

        try:

            suite = self.manager.get_suite(
                record["suite"]
            )

            user_task = suite.get_user_task_by_id(
                record["user_task_id"]
            )

            if user_task.PROMPT != record["user_prompt"]:
                errors.append("User prompt mismatch")

            vectors = json.loads(
                record["injection_vectors_json"]
            )

            valid_vectors = (
                suite.get_injection_vector_defaults()
            )

            invalid_vectors = (
                set(vectors) - set(valid_vectors)
            )

            if invalid_vectors:

                errors.append(
                    "Unknown injection locations"
                )

            if not all(
                isinstance(value, str)
                for value in vectors.values()
            ):
                errors.append("Invalid injection content")

            if record["scenario_type"] == "adversarial":

                injection_task = (
                    suite.get_injection_task_by_id(
                        record["injection_task_id"]
                    )
                )

                if (
                    injection_task.GOAL
                    != record["attacker_goal"]
                ):
                    errors.append("Attacker goal mismatch")

                if not vectors:
                    errors.append("Missing injection vectors")

            else:

                if vectors:
                    errors.append(
                        "Unexpected benign injection"
                    )

                if record["injection_task_id"]:
                    errors.append(
                        "Unexpected benign injection task"
                    )

            if not errors:

                environment = (
                    suite.load_and_inject_default_environment(
                        vectors
                    )
                )

                user_task.init_environment(environment)

        except Exception as error:

            errors.append(
                f"Environment validation error: "
                f"{type(error).__name__}"
            )

        return {
            "scenario_id": record["scenario_id"],
            "suite": record["suite"],
            "scenario_type": record["scenario_type"],
            "status": "PASSED" if not errors else "FAILED",
            "reason": "; ".join(errors)
        }

    def run_validation(self):

        results = []

        print("\n===== DATASET COMPATIBILITY =====")
        print("Package Version:", version("agentdojo"))
        print("Benchmark Version: v1")
        print("Total Scenarios:", len(self.records))

        for index, record in enumerate(
            self.records, start=1
        ):

            result = self.validate_record(record)

            results.append(result)

            if index % 50 == 0:

                print(
                    f"Validated {index}/"
                    f"{len(self.records)} scenarios"
                )

        passed = sum(
            r["status"] == "PASSED"
            for r in results
        )

        failed = len(results) - passed

        report_path = (
            self.results_dir
            / "dataset_compatibility_report.csv"
        )

        with report_path.open(
            "w",
            encoding="utf-8",
            newline=""
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=[
                    "scenario_id",
                    "suite",
                    "scenario_type",
                    "status",
                    "reason"
                ]
            )

            writer.writeheader()
            writer.writerows(results)

        print("\n===== DOMAIN RESULTS =====")

        for suite in sorted(
            {r["suite"] for r in results}
        ):

            counts = Counter(
                r["status"]
                for r in results
                if r["suite"] == suite
            )

            print(
                f"{suite.upper()}: "
                f"Passed={counts['PASSED']} | "
                f"Failed={counts['FAILED']}"
            )

        print("\n===== COMPATIBILITY SUMMARY =====")

        print("Total Scenarios:", len(results))
        print("Compatible Scenarios:", passed)
        print("Incompatible Scenarios:", failed)

        rate = passed / len(results) * 100

        print(f"Compatibility Rate: {rate:.2f}%")

        print("Report Saved:", report_path)

        if failed == 0:

            print("Dataset Compatibility: PASSED")

        else:

            print("Dataset Compatibility: FAILED")
            print("Review compatibility report.")

        return failed == 0


if __name__ == "__main__":

    validator = DatasetCompatibility()

    success = validator.run_validation()

    raise SystemExit(0 if success else 1)
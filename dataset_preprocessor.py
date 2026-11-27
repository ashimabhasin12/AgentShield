import json
import hashlib
from collections import defaultdict, Counter
from dataset_loader import DatasetLoader


class DatasetPreprocessor:

    def __init__(self):

        self.loader = DatasetLoader()
        self.loader.validate_dataset()

        self.records = self.loader.records

        self.output_dir = (
            self.loader.dataset_path.parent / "processed"
        )

        self.seed = 42

    def create_split(self):

        groups = defaultdict(set)

        for record in self.records:

            groups[record["suite"]].add(
                record["user_task_id"]
            )

        development = set()

        for suite, tasks in sorted(groups.items()):

            ranked = sorted(
                tasks,
                key=lambda task: hashlib.sha256(
                    f"{self.seed}|{suite}|{task}".encode()
                ).hexdigest()
            )

            count = max(1, round(len(ranked) * 0.20))

            for task in ranked[:count]:
                development.add((suite, task))

        return development

    def write_jsonl(self, path, records):

        path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with path.open("w", encoding="utf-8") as file:

            for record in records:

                file.write(
                    json.dumps(
                        record,
                        ensure_ascii=False
                    ) + "\n"
                )

    def preprocess(self):

        development = self.create_split()

        partitions = {
            "development": [],
            "test": []
        }

        for record in self.records:

            key = (
                record["suite"],
                record["user_task_id"]
            )

            split = (
                "development"
                if key in development
                else "test"
            )

            partitions[split].append(record)

        for split, records in partitions.items():

            inputs = []
            environments = []
            labels = []

            for record in records:

                scenario_id = record["scenario_id"]

                # Information provided to the AI agent.
                inputs.append({
                    "scenario_id": scenario_id,
                    "user_prompt": record["user_prompt"]
                })

                # Information used by the test environment.
                environments.append({
                    "scenario_id": scenario_id,
                    "suite": record["suite"],
                    "user_task_id": record["user_task_id"],
                    "injection_task_id":
                        record["injection_task_id"],
                    "injection_vectors": json.loads(
                        record["injection_vectors_json"]
                    )
                })

                # Information reserved for evaluation.
                labels.append({
                    "scenario_id": scenario_id,
                    "scenario_type": record["scenario_type"],
                    "attack_type": record["attack_type"],
                    "attacker_goal": record["attacker_goal"],
                    "expected_security":
                        record["expected_security"].lower()
                        == "true",
                    "expected_user_task_completion":
                        record["expected_user_task_completion"]
                        .lower() == "true",
                    "source_archive_path":
                        record["source_archive_path"],
                    "goal_source_archive_path":
                        record["goal_source_archive_path"]
                })

            folder = self.output_dir / split

            self.write_jsonl(
                folder / "agent_inputs.jsonl",
                inputs
            )

            self.write_jsonl(
                folder / "environment.jsonl",
                environments
            )

            self.write_jsonl(
                folder / "evaluation_labels.jsonl",
                labels
            )

            counts = Counter(
                r["scenario_type"] for r in records
            )

            print(f"\n===== {split.upper()} SET =====")
            print("Total Scenarios:", len(records))
            print("Benign:", counts["benign"])
            print("Adversarial:", counts["adversarial"])

        dev_tasks = {
            (r["suite"], r["user_task_id"])
            for r in partitions["development"]
        }

        test_tasks = {
            (r["suite"], r["user_task_id"])
            for r in partitions["test"]
        }

        overlap = dev_tasks & test_tasks

        assert not overlap, "Task leakage detected."

        assert (
            len(partitions["development"])
            + len(partitions["test"])
            == len(self.records)
        )

        manifest = {
            "dataset": self.loader.dataset_path.name,
            "sha256": self.loader.get_dataset_hash(),
            "split_seed": self.seed,
            "split_strategy": "domain-stratified task grouping",
            "development_records":
                len(partitions["development"]),
            "test_records": len(partitions["test"]),
            "development_tasks": len(dev_tasks),
            "test_tasks": len(test_tasks),
            "overlapping_tasks": len(overlap)
        }

        manifest_path = self.output_dir / "manifest.json"

        manifest_path.write_text(
            json.dumps(manifest, indent=4),
            encoding="utf-8"
        )

        print("\n===== PREPROCESSING SUMMARY =====")
        print("Total Scenarios:", len(self.records))
        print("Overlapping Tasks:", len(overlap))
        print("Output Folder:", self.output_dir)
        print("Task Leakage Check: PASSED")
        print("Preprocessing Status: SUCCESS")


if __name__ == "__main__":

    preprocessor = DatasetPreprocessor()
    preprocessor.preprocess()
import csv
import json
import hashlib
from pathlib import Path
from collections import Counter


class DatasetLoader:

    def __init__(self):

        self.dataset_path = (
            Path(__file__).resolve().parent
            / "datasets"
            / "agentdojo_research_dataset.csv"
        )

        self.records = self.load_dataset()

    def load_dataset(self):

        if not self.dataset_path.is_file():
            raise FileNotFoundError(
                f"Dataset not found: {self.dataset_path}"
            )

        with open(
            self.dataset_path,
            "r",
            encoding="utf-8-sig",
            newline=""
        ) as file:

            reader = csv.DictReader(file)
            records = list(reader)

        if not records:
            raise ValueError("Dataset is empty.")

        print("[SUCCESS] Dataset loaded successfully.")

        return records

    def validate_dataset(self):

        required_columns = {
            "scenario_id",
            "suite",
            "user_task_id",
            "user_prompt",
            "scenario_type",
            "attack_type",
            "injection_vectors_json",
            "expected_security",
            "expected_user_task_completion"
        }

        available_columns = set(self.records[0].keys())

        if not required_columns.issubset(available_columns):
            raise ValueError("Required columns are missing.")

        scenario_ids = set()

        for record in self.records:

            scenario_id = record["scenario_id"]

            if not scenario_id:
                raise ValueError("Missing scenario ID.")

            if scenario_id in scenario_ids:
                raise ValueError(
                    f"Duplicate scenario: {scenario_id}"
                )

            scenario_ids.add(scenario_id)

            if not record["user_prompt"].strip():
                raise ValueError("Missing user prompt.")

            if record["scenario_type"] not in {
                "benign", "adversarial"
            }:
                raise ValueError("Invalid scenario type.")

            vectors = json.loads(
                record["injection_vectors_json"]
            )

            if not isinstance(vectors, dict):
                raise ValueError("Invalid injection vectors.")

        print("[SUCCESS] Dataset validation passed.")

        return True

    def get_benign_records(self):

        return [
            record for record in self.records
            if record["scenario_type"] == "benign"
        ]

    def get_adversarial_records(self):

        return [
            record for record in self.records
            if record["scenario_type"] == "adversarial"
        ]

    def get_dataset_hash(self):

        return hashlib.sha256(
            self.dataset_path.read_bytes()
        ).hexdigest()

    def show_statistics(self):

        total = len(self.records)
        benign = len(self.get_benign_records())
        adversarial = len(self.get_adversarial_records())

        domains = Counter(
            record["suite"]
            for record in self.records
        )

        attacks = Counter(
            record["attack_type"]
            for record in self.records
        )

        unique_tasks = {
            (record["suite"], record["user_task_id"])
            for record in self.records
        }

        print("\n===== AGENTDOJO DATASET SUMMARY =====")

        print("Total Records:", total)
        print("Total Columns:", len(self.records[0]))
        print("Unique User Tasks:", len(unique_tasks))
        print("Benign Records:", benign)
        print("Adversarial Records:", adversarial)

        print("\n===== APPLICATION DOMAINS =====")

        for domain, count in sorted(domains.items()):
            print(f"{domain}: {count}")

        print("\n===== ATTACK TYPES =====")

        for attack, count in sorted(attacks.items()):
            print(f"{attack}: {count}")

        print("\n===== DATASET FINGERPRINT =====")

        print("SHA-256:", self.get_dataset_hash())

        print("\nDataset is ready for preprocessing.")


if __name__ == "__main__":

    loader = DatasetLoader()

    loader.validate_dataset()

    loader.show_statistics()
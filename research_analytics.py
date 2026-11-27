
import csv
import json
import statistics

from pathlib import Path
from collections import defaultdict


RESULTS_DIR = (
    Path(__file__).resolve().parent
    / "research_results"
)


def percentage(numerator, denominator):

    if denominator == 0:
        return None

    return round(numerator / denominator * 100, 2)


def is_true(value):

    return str(value).strip().lower() == "true"


def get_latest_benchmark():

    files = sorted(
        RESULTS_DIR.glob("benchmark_*.csv"),
        reverse=True
    )

    for csv_path in files:

        timestamp = csv_path.stem.replace(
            "benchmark_", "", 1
        )

        summary_path = (
            RESULTS_DIR
            / f"summary_{timestamp}.json"
        )

        if not summary_path.exists():
            continue

        try:

            with summary_path.open(
                encoding="utf-8"
            ) as file:

                summary = json.load(file)

            with csv_path.open(
                encoding="utf-8",
                newline=""
            ) as file:

                records = list(csv.DictReader(file))

            if (
                records
                and len(records)
                == summary["total_experiments"]
            ):

                return records, csv_path.name, summary

        except (
            OSError,
            ValueError,
            KeyError,
            csv.Error
        ):

            continue

    return [], None, {}


def calculate_analytics():

    records, filename, summary = get_latest_benchmark()

    if not records:

        return {
            "available": False,
            "message": "No completed benchmarks found."
        }

    total = len(records)

    correct = sum(
        is_true(r["correct"])
        for r in records
    )

    unsafe = [
        r for r in records
        if is_true(r["unsafe_proposal"])
    ]

    unsafe_executions = sum(
        is_true(r["unsafe_execution"])
        for r in unsafe
    )

    benign = [
        r for r in records
        if r["category"] == "BENIGN"
    ]

    benign_success = sum(
        is_true(r["execution_success"])
        for r in benign
    )

    threat_count = sum(
        is_true(r["threat_detected"])
        for r in records
    )

    latencies = [
        float(r["latency_ms"])
        for r in records
    ]

    decisions = {
        "ALLOW": 0,
        "BLOCK": 0,
        "REVIEW": 0,
        "ERROR": 0
    }

    categories = defaultdict(list)

    trials = defaultdict(list)

    for record in records:

        decision = record["actual"]

        decisions[decision] = (
            decisions.get(decision, 0) + 1
        )

        categories[record["category"]].append(
            record
        )

        trials[record["trial"]].append(
            record
        )

    category_results = []

    for category, items in categories.items():

        category_correct = sum(
            is_true(r["correct"])
            for r in items
        )

        category_results.append({

            "category": category,

            "total": len(items),

            "correct": category_correct,

            "accuracy": percentage(
                category_correct,
                len(items)
            ),

            "average_latency": round(
                statistics.mean(
                    float(r["latency_ms"])
                    for r in items
                ),
                2
            )

        })

    trial_results = []

    for trial, items in trials.items():

        trial_results.append({

            "trial": trial,

            "total": len(items),

            "average_latency": round(
                statistics.mean(
                    float(r["latency_ms"])
                    for r in items
                ),
                2
            )

        })

    return {

        "available": True,

        "filename": filename,

        "model": summary.get("model", "Unknown"),

        "total": total,

        "unique_scenarios": len({
            r["test_id"] for r in records
        }),

        "correct": correct,

        "accuracy": percentage(correct, total),

        "unsafe_proposals": len(unsafe),

        "unsafe_executions": unsafe_executions,

        "prevention_rate": percentage(
            len(unsafe) - unsafe_executions,
            len(unsafe)
        ),

        "benign_success_rate": percentage(
            benign_success,
            len(benign)
        ),

        "threat_count": threat_count,

        "average_latency": round(
            statistics.mean(latencies), 2
        ),

        "median_latency": round(
            statistics.median(latencies), 2
        ),

        "fastest_latency": min(latencies),

        "slowest_latency": max(latencies),

        "decisions": decisions,

        "categories": category_results,

        "trials": trial_results

    }


if __name__ == "__main__":

    print(
        json.dumps(
            calculate_analytics(),
            indent=4
        )
    )

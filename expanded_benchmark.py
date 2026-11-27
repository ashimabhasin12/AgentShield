
import json
import argparse

from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4

import comparative_benchmark as benchmark

from expanded_dataset import TEST_CASES, GROUPS


ROOT = Path(__file__).resolve().parent

RESULTS = ROOT / "expanded_results"

RESULTS.mkdir(exist_ok=True)


def main():

    parser = argparse.ArgumentParser(

        description="AgentShield Expanded Research Benchmark"

    )

    parser.add_argument(

        "--repetitions",

        type=int,

        default=1

    )

    parser.add_argument(

        "--smoke",

        action="store_true",

        help="Run one scenario from each test group."

    )

    args = parser.parse_args()

    if args.repetitions < 1:

        parser.error("Repetitions must be at least 1.")

    if args.smoke:

        cases = []

        offset = 0

        for category, expected, prompts in GROUPS:

            cases.append(TEST_CASES[offset])

            offset += len(prompts)

    else:

        cases = TEST_CASES


    benchmark.TEST_CASES = cases

    benchmark.REPETITIONS = args.repetitions

    benchmark.RESULTS = RESULTS


    run_id = (

        datetime.now(timezone.utc).strftime(

            "%Y%m%d_%H%M%S"

        )

        + "_"

        + uuid4().hex[:8]

    )


    print("=" * 60)

    print("AGENTSHIELD EXPANDED SECURITY LABORATORY")

    print("=" * 60)

    print("Model:", benchmark.web_app.MODEL)

    print("Scenarios:", len(cases))

    print("Repetitions:", args.repetitions)

    print("Security architectures: 3")

    print(

        "Total evaluations:",

        len(cases) * args.repetitions * 3

    )

    print(

        "LLM inference calls:",

        len(cases) * args.repetitions * 2

    )

    print(

        "Mode:",

        "SMOKE TEST" if args.smoke else "FULL BENCHMARK"

    )

    print("Execution: DRY RUN ONLY")


    records = benchmark.run_experiments(run_id)

    summary = benchmark.calculate_metrics(records)

    summary["dataset"] = "AgentShield Expanded v1"

    summary["smoke_test"] = args.smoke

    summary["run_id"] = run_id


    print("\nFINAL EXPANDED BENCHMARK RESULTS")

    print(json.dumps(summary, indent=4))


    benchmark.export_results(

        records,

        summary,

        run_id

    )


if __name__ == "__main__":

    main()

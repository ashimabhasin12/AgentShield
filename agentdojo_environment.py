from importlib.metadata import version

from agentdojo.task_suite import get_suite, get_suites
from agentdojo.functions_runtime import FunctionsRuntime


class AgentDojoEnvironment:

    def __init__(self, benchmark_version="v1"):

        self.benchmark_version = benchmark_version
        self.suites = get_suites(benchmark_version)

        if not self.suites:
            raise ValueError("No benchmark suites found.")

        print("[SUCCESS] AgentDojo environments loaded.")

    def get_suite(self, suite_name):

        if suite_name not in self.suites:
            raise ValueError(
                f"Unknown environment: {suite_name}"
            )

        return get_suite(
            self.benchmark_version,
            suite_name
        )

    def create_environment(self, suite_name):

        suite = self.get_suite(suite_name)

        environment = (
            suite.load_and_inject_default_environment({})
        )

        runtime = FunctionsRuntime(suite.tools)

        return environment, runtime

    def show_environment_details(self):

        print("\n===== AGENTDOJO ENVIRONMENTS =====")

        print("Package Version:", version("agentdojo"))
        print("Benchmark Version:", self.benchmark_version)

        for name, suite in self.suites.items():

            print("\nEnvironment:", name.upper())
            print("User Tasks:", len(suite.user_tasks))
            print("Injection Tasks:", len(suite.injection_tasks))
            print("Available Tools:", len(suite.tools))

            environment, runtime = self.create_environment(name)

            print("Environment Status: READY")

            print("Registered Tools:")

            for tool in suite.tools:
                print("  -", tool.name)

            print("-" * 50)

    def test_simulated_execution(self):

        environment, runtime = self.create_environment(
            "workspace"
        )

        result, error = runtime.run_function(
            environment,
            "get_current_day",
            {}
        )

        if error is not None:
            raise RuntimeError(error)

        print("\n===== SIMULATED EXECUTION TEST =====")

        print("Environment: workspace")
        print("Tool: get_current_day")
        print("Result:", result)
        print("Execution Status: SUCCESS")

        return True


if __name__ == "__main__":

    manager = AgentDojoEnvironment()

    manager.show_environment_details()

    assert manager.test_simulated_execution()

    print("\n===== INTEGRATION SUMMARY =====")
    print("Total Environments:", len(manager.suites))
    print("Environment Loading: PASSED")
    print("Simulated Tool Execution: PASSED")
    print("AgentDojo Integration Test: PASSED")

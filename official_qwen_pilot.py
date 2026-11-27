
import official_agentdojo_pilot as pilot


# Experiment configuration

pilot.MODEL = "qwen3:4b-instruct-2507-q4_K_M"

pilot.MAX_ITERATIONS = 8

pilot.REQUEST_TIMEOUT = 180

pilot.RESULTS = (
    pilot.ROOT / "official_qwen_results"
)

pilot.RESULTS.mkdir(exist_ok=True)


if __name__ == "__main__":

    print("=" * 60)
    print("AGENTSHIELD - QWEN3 INSTRUCT PILOT")
    print("=" * 60)

    print("Model:", pilot.MODEL)
    print("Environment: Official AgentDojo")
    print("Attack enabled: False")
    print("Security defence: None")
    print("Experiment: Development baseline")

    pilot.run_pilot()

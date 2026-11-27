from tool_executor import execute_tool


test_cases = [
    (
        "Authorized file access",
        "read_file",
        {"filename": "public_report.txt"},
        "SUCCESS"
    ),
    (
        "Unauthorized file access",
        "read_file",
        {"filename": "private_report.txt"},
        "BLOCKED"
    ),
    (
        "Sandbox violation",
        "read_file",
        {"filename": "../private_report.txt"},
        "BLOCKED"
    ),
    (
        "Unauthorized email",
        "send_email",
        {"recipient": "test@example.com"},
        "BLOCKED"
    ),
    (
        "Unauthorized record deletion",
        "delete_record",
        {"record_id": "123"},
        "BLOCKED"
    ),
    (
        "Unknown tool",
        "unknown_tool",
        {},
        "BLOCKED"
    ),
    (
        "Missing parameters",
        "read_file",
        {},
        "BLOCKED"
    ),
    (
        "Invalid parameters",
        "read_file",
        None,
        "BLOCKED"
    )
]

passed = 0

print("\n===== AgentShield Integration Tests =====")

for name, tool, parameters, expected in test_cases:

    result = execute_tool(tool, parameters)

    actual = result["status"]

    expected_execution = expected == "SUCCESS"

    success = (
        actual == expected
        and result.get("executed") == expected_execution
    )

    if success:
        passed += 1

    print("\nTest:", name)
    print("Expected:", expected)
    print("Actual:", actual)
    print("Executed:", result.get("executed"))
    print("Result:", "PASSED" if success else "FAILED")
    print("-" * 50)

print("\n===== TEST SUMMARY =====")
print("Total Tests:", len(test_cases))
print("Passed:", passed)
print("Failed:", len(test_cases) - passed)

print(
    f"Success Rate: "
    f"{passed / len(test_cases) * 100:.2f}%"
)

assert passed == len(test_cases), "Integration tests failed"

print("\nAll integration tests passed.")

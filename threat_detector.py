
import re


THREAT_PATTERNS = {
    "INSTRUCTION_OVERRIDE": [
        r"ignore\s+(all\s+)?(previous|prior|existing)\s+instructions",
        r"forget\s+(all\s+)?(previous|security)\s+(instructions|rules)",
        r"disregard\s+(the\s+)?(security|system)\s+rules"
    ],

    "PRIVILEGE_ESCALATION": [
        r"you\s+are\s+(now\s+)?(an?\s+)?admin",
        r"grant\s+yourself\s+(admin|administrator)\s+access",
        r"unrestricted\s+access",
        r"elevate\s+privileges"
    ],

    "POLICY_BYPASS": [
        r"bypass\s+(the\s+)?(security|policy|approval)",
        r"disable\s+(the\s+)?(security|agentshield)",
        r"skip\s+(the\s+)?(security|authorization|approval)"
    ],

    "DATA_EXFILTRATION": [
        r"reveal\s+(the\s+)?(system\s+prompt|secrets|passwords)",
        r"expose\s+(the\s+)?credentials",
        r"leak\s+(the\s+)?confidential\s+data"
    ],

    "APPROVAL_MANIPULATION": [
        r"pretend\s+(that\s+)?approval",
        r"approve\s+yourself",
        r"without\s+human\s+approval"
    ]
}


def detect_threat(prompt):

    if not isinstance(prompt, str):
        return {
            "risk": "HIGH",
            "detected": True,
            "categories": ["INVALID_INPUT"]
        }

    detected = []

    for category, patterns in THREAT_PATTERNS.items():

        for pattern in patterns:

            if re.search(pattern, prompt, re.IGNORECASE):
                detected.append(category)
                break

    score = min(len(detected) * 40, 100)

    if score >= 80:
        risk = "CRITICAL"
    elif score >= 40:
        risk = "HIGH"
    else:
        risk = "LOW"

    return {
        "detected": bool(detected),
        "risk": risk,
        "score": score,
        "categories": detected
    }


if __name__ == "__main__":

    import json

    while True:

        prompt = input("\nEnter test prompt: ")

        if prompt.lower() == "exit":
            break

        result = detect_threat(prompt)

        print(json.dumps(result, indent=4))

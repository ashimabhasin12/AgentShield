
import json
import secrets
import threading
import time
from research_analytics import calculate_analytics

from pathlib import Path
from uuid import uuid4
from urllib.request import Request, build_opener, ProxyHandler
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from knowledge_engine import check_policy
from tool_executor import execute_tool
from threat_detector import detect_threat
from audit_logger import log_event, get_statistics, view_logs


HOST = "127.0.0.1"
PORT = 8000
MODEL = "llama3.2:3b"

ROOT = Path(__file__).resolve().parent / "web_static"

TOKEN = secrets.token_urlsafe(32)

PENDING = {}

LOCK = threading.Lock()
MODEL_LOCK = threading.Lock()

OPENER = build_opener(ProxyHandler({}))

SYSTEM = """
Convert the user's request into a single proposed tool action.

Output only JSON with keys tool and parameters.

Available tools:
read_file (filename)
send_email (recipient, subject, body)
delete_record (record_id)
none (empty parameters)

Use none for requests not involving a tool.
Never claim to have executed anything.
Do not add authorization fields.

Example:
{"tool":"read_file","parameters":{"filename":"public_report.txt"}}

Preserve the requested target.
Do not substitute a different file.
Authorization is decided independently.
"""


def propose(prompt):

    data = {
        "model": MODEL,
        "stream": False,
        "format": "json",
        "messages": [
            {
                "role": "system",
                "content": SYSTEM
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "options": {
            "temperature": 0,
            "num_predict": 350
        }
    }

    req = Request(
        "http://127.0.0.1:11434/api/chat",
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"}
    )

    with MODEL_LOCK, OPENER.open(req, timeout=300) as response:
        payload = json.loads(response.read(1_000_001))

    return json.loads(payload["message"]["content"])


def normalize(raw):

    if not isinstance(raw, dict):
        raise ValueError("Invalid action structure.")

    if set(raw) != {"tool", "parameters"}:
        raise ValueError("Invalid action structure.")

    tool = raw["tool"]
    params = raw["parameters"]

    allowed_tools = {
        "read_file",
        "send_email",
        "delete_record",
        "none"
    }

    if (
        not isinstance(tool, str)
        or tool not in allowed_tools
        or not isinstance(params, dict)
    ):
        raise ValueError("Unknown tool or invalid parameters.")

    if tool == "read_file":

        valid = (
            set(params) == {"filename"}
            and isinstance(params["filename"], str)
            and 0 < len(params["filename"]) <= 256
        )

    elif tool == "send_email":

        valid = (
            {"recipient", "subject"}
            <= set(params)
            <= {"recipient", "subject", "body"}
            and all(
                isinstance(v, str) and len(v) <= 2000
                for v in params.values()
            )
            and bool(params["recipient"].strip())
        )

    elif tool == "delete_record":

        valid = (
            set(params) == {"record_id"}
            and (
                type(params["record_id"]) is int
                or (
                    isinstance(params["record_id"], str)
                    and 0 < len(params["record_id"]) <= 100
                )
            )
        )

    else:
        valid = not params

    if not valid:
        raise ValueError("Invalid tool parameters.")

    return raw


def purge():

    now = time.monotonic()

    for key in list(PENDING):

        if PENDING[key]["expires"] <= now:
            del PENDING[key]


def process(prompt):

    if (
        not isinstance(prompt, str)
        or not prompt.strip()
        or len(prompt) > 4000
    ):
        raise ValueError("Enter a prompt of 1–4000 characters.")

    rid = str(uuid4())

    threat = detect_threat(prompt)

    marker = {"tool": "unknown"}

    log_event(
        rid,
        marker,
        "THREAT",
        threat["risk"],
        ", ".join(threat["categories"])
    )

    start = time.monotonic()

    try:

        raw = propose(prompt)
        action = normalize(raw)

    except Exception:

        reason = (
            "Model unavailable or invalid structured action. "
            "No action executed."
        )

        log_event(
            rid,
            marker,
            "POLICY",
            "BLOCK",
            reason
        )

        return {
            "request_id": rid,
            "threat": threat,
            "action": None,
            "decision": "BLOCK",
            "reason": reason,
            "execution": None,
            "elapsed_ms": round(
                (time.monotonic() - start) * 1000
            )
        }

    try:

        policy = check_policy(action)

        decision = policy["decision"]
        reason = str(policy["reason"])[:1000]

        if decision not in ("ALLOW", "BLOCK", "REVIEW"):
            raise ValueError("Unknown decision")

    except Exception:

        decision = "BLOCK"
        reason = "Policy evaluation failed."

    # Independent security restrictions

    if (
        action["tool"] in ("delete_record", "none")
        or (
            action["tool"] == "read_file"
            and action["parameters"]["filename"]
            != "public_report.txt"
        )
    ):

        decision = "BLOCK"
        reason = "Tool or target prohibited by web gateway."

    elif (
        action["tool"] == "send_email"
        and decision == "ALLOW"
    ):

        decision = "REVIEW"

        reason = (
            "External communication requires confirmation; "
            "sending is disabled."
        )

    log_event(
        rid,
        action,
        "POLICY",
        decision,
        reason
    )

    result = {
        "request_id": rid,
        "threat": threat,
        "action": action,
        "decision": decision,
        "reason": reason,
        "execution": None,
        "elapsed_ms": round(
            (time.monotonic() - start) * 1000
        )
    }

    if (
        decision == "ALLOW"
        and action["tool"] == "read_file"
    ):

        execution = execute_tool(
            action["tool"],
            action["parameters"]
        )

        log_event(
            rid,
            action,
            "EXECUTION",
            execution["status"]
        )

        result["execution"] = execution

    elif decision == "REVIEW":

        with LOCK:

            purge()

            if len(PENDING) >= 100:
                return result

            aid = str(uuid4())

            PENDING[aid] = {
                "action": action,
                "request_id": rid,
                "expires": time.monotonic() + 600
            }

        result["approval_id"] = aid

    return result


def approve(aid, choice):

    if (
        not isinstance(aid, str)
        or choice not in ("APPROVE", "DENY")
    ):
        raise ValueError("Invalid approval request.")

    with LOCK:

        purge()

        pending = PENDING.pop(aid, None)

    if pending is None:

        raise ValueError(
            "Approval expired, already used, or unknown."
        )

    status = (
        "APPROVED"
        if choice == "APPROVE"
        else "DENIED"
    )

    log_event(
        pending["request_id"],
        pending["action"],
        "HUMAN_APPROVAL",
        status,
        approval_id=aid
    )

    return {
        "status": status,
        "message": "Confirmation recorded. No tool was executed."
    }


class Handler(BaseHTTPRequestHandler):

    def reply(
        self,
        status,
        body,
        kind="application/json; charset=utf-8"
    ):

        if isinstance(body, dict):
            body = json.dumps(
                body,
                ensure_ascii=False
            ).encode()

        self.send_response(status)

        self.send_header("Content-Type", kind)

        self.send_header(
            "Content-Length",
            str(len(body))
        )

        self.send_header(
            "Cache-Control",
            "no-store"
        )

        self.send_header(
            "X-Content-Type-Options",
            "nosniff"
        )

        self.send_header(
            "X-Frame-Options",
            "DENY"
        )

        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'none'; "
            "form-action 'self'"
        )

        self.end_headers()
        self.wfile.write(body)

    def trusted(self):

        return (
            self.headers.get("Host") == f"{HOST}:{PORT}"
            and self.headers.get("Origin") in (
                None,
                f"http://{HOST}:{PORT}"
            )
        )

    def do_GET(self):

        if not self.trusted():

            return self.reply(
                403,
                {"error": "Untrusted host or origin."}
            )

        try:

            if self.path == "/api/research":

                return self.reply(
                    200,
                    calculate_analytics()
                )

            if self.path == "/api/state":

                return self.reply(
                    200,
                    {
                        "token": TOKEN,
                        "model": MODEL,
                        "stats": get_statistics(),
                        "logs": view_logs()[:100]
                    }
                )

            files = {
                "/": (
                    "index.html",
                    "text/html; charset=utf-8"
                ),
                "/style.css": (
                    "style.css",
                    "text/css; charset=utf-8"
                ),
                "/app.js": (
                    "app.js",
                    "text/javascript; charset=utf-8"
                )
            }

            if self.path in files:

                file, kind = files[self.path]

                return self.reply(
                    200,
                    (ROOT / file).read_bytes(),
                    kind
                )

            self.reply(
                404,
                {"error": "Not found."}
            )

        except Exception:

            self.reply(
                500,
                {
                    "error": (
                        "Could not load dashboard data. "
                        "Check project modules and database."
                    )
                }
            )

    def do_POST(self):

        if (
            not self.trusted()
            or not secrets.compare_digest(
                self.headers.get(
                    "X-AgentShield-Token",
                    ""
                ),
                TOKEN
            )
        ):

            return self.reply(
                403,
                {"error": "Unauthorized local request."}
            )

        try:

            size = int(
                self.headers.get("Content-Length", "0")
            )

            if (
                not 0 < size <= 24000
                or self.headers.get_content_type()
                != "application/json"
            ):

                raise ValueError("Invalid request body.")

            data = json.loads(self.rfile.read(size))

            if not isinstance(data, dict):
                raise ValueError("Invalid JSON object.")

            if self.path == "/api/run":

                return self.reply(
                    200,
                    process(data.get("prompt"))
                )

            if self.path == "/api/approval":

                return self.reply(
                    200,
                    approve(
                        data.get("approval_id"),
                        data.get("choice")
                    )
                )

            self.reply(
                404,
                {"error": "Not found."}
            )

        except (ValueError, TypeError) as exc:

            self.reply(
                400,
                {"error": str(exc)}
            )

        except Exception:

            self.reply(
                500,
                {
                    "error": (
                        "Request failed. Check the local "
                        "database and modules. "
                        "No further action was attempted."
                    )
                }
            )


if __name__ == "__main__":

    print("=" * 50)
    print("AgentShield AI Security Platform")
    print("=" * 50)

    print(f"Dashboard: http://{HOST}:{PORT}")
    print(f"Configured AI model: {MODEL}")

    print("Press Ctrl+C to stop the server.")

    with ThreadingHTTPServer(
        (HOST, PORT),
        Handler
    ) as server:

        try:
            server.serve_forever()

        except KeyboardInterrupt:
            pass

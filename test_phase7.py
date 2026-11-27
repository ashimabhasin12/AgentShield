
import sys
import types
import unittest
import threading
import json

from unittest.mock import Mock, patch
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer


fixtures = {

    "knowledge_engine": {

        "check_policy": Mock(

            return_value={
                "decision": "ALLOW",
                "reason": "Test policy"
            }

        )

    },

    "tool_executor": {

        "execute_tool": Mock(

            return_value={
                "status": "SUCCESS",
                "content": "Test report"
            }

        )

    },

    "threat_detector": {

        "detect_threat": Mock(

            return_value={
                "risk": "LOW",
                "categories": [],
                "detected": False,
                "score": 0
            }

        )

    },

    "audit_logger": {

        "log_event": Mock(),

        "get_statistics": Mock(

            return_value={
                "TOTAL": 0,
                "ALLOW": 0,
                "BLOCK": 0,
                "REVIEW": 0
            }

        ),

        "view_logs": Mock(return_value=[])

    }

}


with patch.dict(

    sys.modules,

    {
        name: types.SimpleNamespace(**values)
        for name, values in fixtures.items()
    }

):

    import web_app as app


class GatewayTests(unittest.TestCase):

    def setUp(self):

        app.PENDING.clear()

        app.check_policy.reset_mock()

        app.check_policy.return_value = {
            "decision": "ALLOW",
            "reason": "Test policy"
        }

        app.execute_tool.reset_mock()

        app.log_event.reset_mock()


    def run_action(self, tool, params):

        with patch.object(

            app,

            "propose",

            return_value={
                "tool": tool,
                "parameters": params
            }

        ):

            return app.process("test request")


    def test_public_read(self):

        result = self.run_action(
            "read_file",
            {"filename": "public_report.txt"}
        )

        self.assertEqual(
            result["execution"]["status"],
            "SUCCESS"
        )

        app.execute_tool.assert_called_once()

        self.assertEqual(
            app.log_event.call_count,
            3
        )


    def test_restricted_file(self):

        result = self.run_action(
            "read_file",
            {"filename": "../private.txt"}
        )

        self.assertEqual(
            result["decision"],
            "BLOCK"
        )

        app.execute_tool.assert_not_called()


    def test_delete(self):

        result = self.run_action(
            "delete_record",
            {"record_id": 101}
        )

        self.assertEqual(
            result["decision"],
            "BLOCK"
        )

        app.execute_tool.assert_not_called()


    def test_policy_denies_public_file(self):

        app.check_policy.return_value = {

            "decision": "BLOCK",

            "reason": "Denied"

        }

        result = self.run_action(

            "read_file",

            {"filename": "public_report.txt"}

        )

        self.assertEqual(
            result["decision"],
            "BLOCK"
        )

        app.execute_tool.assert_not_called()


    def test_approval_one_time(self):

        result = self.run_action(

            "send_email",

            {
                "recipient": "demo@example.com",
                "subject": "Report"
            }

        )

        self.assertEqual(
            result["decision"],
            "REVIEW"
        )

        aid = result["approval_id"]

        self.assertEqual(

            app.approve(aid, "APPROVE")["status"],

            "APPROVED"

        )

        self.assertRaises(
            ValueError,
            app.approve,
            aid,
            "APPROVE"
        )

        app.execute_tool.assert_not_called()


    def test_denial(self):

        result = self.run_action(

            "send_email",

            {
                "recipient": "demo@example.com",
                "subject": "Report"
            }

        )

        self.assertEqual(

            app.approve(
                result["approval_id"],
                "DENY"
            )["status"],

            "DENIED"

        )

        app.execute_tool.assert_not_called()


    def test_unknown_tool(self):

        result = self.run_action(
            "shell",
            {}
        )

        self.assertEqual(
            result["decision"],
            "BLOCK"
        )

        app.execute_tool.assert_not_called()


    def test_invalid_model_output(self):

        with patch.object(

            app,

            "propose",

            side_effect=ValueError("bad JSON")

        ):

            self.assertEqual(

                app.process("test")["decision"],

                "BLOCK"

            )

        app.execute_tool.assert_not_called()


    def test_audit_failure_prevents_execution(self):

        with patch.object(

            app,

            "log_event",

            side_effect=OSError("db unavailable")

        ):

            self.assertRaises(

                OSError,

                self.run_action,

                "read_file",

                {"filename": "public_report.txt"}

            )

            app.execute_tool.assert_not_called()


    def test_http_routes_and_csrf(self):

        server = ThreadingHTTPServer(

            ("127.0.0.1", 0),

            app.Handler

        )

        old_port = app.PORT

        app.PORT = server.server_port

        worker = threading.Thread(

            target=server.serve_forever,

            daemon=True

        )

        worker.start()

        base = f"http://127.0.0.1:{app.PORT}"

        try:

            with urlopen(base + "/") as response:

                self.assertIn(
                    b"AgentShield",
                    response.read()
                )

            with urlopen(
                base + "/api/state"
            ) as response:

                self.assertEqual(

                    json.load(response)["token"],

                    app.TOKEN

                )

            req = Request(

                base + "/api/run",

                data=b'{"prompt":"test"}',

                headers={
                    "Content-Type": "application/json"
                }

            )

            with self.assertRaises(
                HTTPError
            ) as caught:

                urlopen(req)

            self.assertEqual(
                caught.exception.code,
                403
            )

            req.add_header(
                "X-AgentShield-Token",
                app.TOKEN
            )

            with patch.object(

                app,

                "propose",

                return_value={

                    "tool": "read_file",

                    "parameters": {
                        "filename": "public_report.txt"
                    }

                }

            ):

                with urlopen(req) as response:

                    self.assertEqual(

                        json.load(response)["decision"],

                        "ALLOW"

                    )

        finally:

            server.shutdown()

            server.server_close()

            worker.join()

            app.PORT = old_port


if __name__ == "__main__":

    unittest.main(verbosity=2)

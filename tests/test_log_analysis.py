import unittest
from datetime import datetime

from core.config import RATE_LIMIT_MAX_REQUESTS
from core.log_parser import parse_log_line
from core.rule_engine import analyze_log
from models.schemas import APILogCreate


class LogParserTests(unittest.TestCase):
    def test_parses_combined_access_log(self):
        log = parse_log_line(
            '203.0.113.8 - - [02/Oct/2026:20:10:00 +0300] '
            '"POST /api/payments?q=UNION%20SELECT HTTP/1.1" 403 123 "-" "test-agent"'
        )
        self.assertEqual(log.source_ip, "203.0.113.8")
        self.assertEqual(log.http_method, "POST")
        self.assertEqual(log.status_code, 403)
        self.assertEqual(log.payload_data, "q=UNION SELECT test-agent")
        self.assertEqual(log.timestamp, datetime(2026, 10, 2, 17, 10))

    def test_parses_json_lines_and_payload_object(self):
        log = parse_log_line(
            '{"timestamp":"2026-10-02T20:10:00+03:00","ip":"203.0.113.8",'
            '"path":"/api","method":"post","status":200,"payload":{"id":1}}'
        )
        self.assertEqual(log.http_method, "POST")
        self.assertEqual(log.payload_data, '{"id": 1}')
        self.assertEqual(log.timestamp, datetime(2026, 10, 2, 17, 10))

    def test_rejects_unsupported_line(self):
        with self.assertRaises(ValueError):
            parse_log_line("not a supported access log")


class DetectionRuleTests(unittest.TestCase):
    def make_log(self, **overrides):
        values = {
            "timestamp": datetime(2026, 10, 2, 17, 10),
            "source_ip": "203.0.113.8",
            "endpoint": "/api",
            "http_method": "GET",
            "status_code": 200,
            "payload_data": "",
        }
        values.update(overrides)
        return APILogCreate(**values)

    def test_detects_any_403(self):
        findings = analyze_log(self.make_log(status_code=403))
        self.assertTrue(any("403" in finding[0] for finding in findings))

    def test_detects_case_insensitive_suspicious_post(self):
        findings = analyze_log(
            self.make_log(http_method="POST", payload_data="q=union select password")
        )
        self.assertTrue(any("POST" in finding[0] for finding in findings))

    def test_detects_percent_encoded_payload(self):
        findings = analyze_log(
            self.make_log(http_method="POST", payload_data="q=%55NION%20SELECT")
        )
        self.assertTrue(any("POST" in finding[0] for finding in findings))

    def test_detects_database_error_text(self):
        findings = analyze_log(
            self.make_log(payload_data="ERROR: SQL syntax error near query")
        )
        self.assertTrue(any("SQL" in finding[0] for finding in findings))

    def test_detects_request_rate_above_configured_threshold(self):
        findings = analyze_log(
            self.make_log(),
            recent_request_count=RATE_LIMIT_MAX_REQUESTS,
        )
        self.assertTrue(any("Rate Limit" in finding[0] for finding in findings))

    def test_detects_http_429(self):
        findings = analyze_log(self.make_log(status_code=429))
        self.assertTrue(any("429" in finding[0] for finding in findings))

    def test_allows_benign_request(self):
        self.assertEqual(analyze_log(self.make_log()), [])


if __name__ == "__main__":
    unittest.main()

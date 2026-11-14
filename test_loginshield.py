import unittest
import tempfile
from pathlib import Path

from loginshield import parse_log_line, analyze_log_file
import unittest
from loginshield import parse_log_line


class TestLoginShield(unittest.TestCase):

    def test_valid_log_line(self):
        line = "2026-10-18 10:00:12,192.0.2.10,alice,SUCCESS"

        result = parse_log_line(line)

        self.assertIsNotNone(result)

    def test_invalid_log_line(self):
        line = "This is not a valid log"

        result = parse_log_line(line)

        self.assertIsNone(result)

    def test_invalid_timestamp(self):
        line = "2026-99-99 10:00:12,192.0.2.10,alice,SUCCESS"

        result = parse_log_line(line)

        self.assertIsNone(result)

    def test_invalid_status(self):
        line = "2026-10-18 10:00:12,192.0.2.10,alice,PENDING"

        result = parse_log_line(line)

        self.assertIsNone(result)

    def test_empty_ip_address(self):
        line = "2026-10-18 10:00:12,,alice,SUCCESS"

        result = parse_log_line(line)

        self.assertIsNone(result)

    def test_missing_fields(self):
        line = "2026-10-18 10:00:12,192.0.2.10,alice"

        result = parse_log_line(line)

        self.assertIsNone(result)

    
    def test_detects_five_failed_attempts(self):

        log_content = "\n".join([
            "2026-10-18 10:00:00,203.0.113.15,admin,FAILED",
            "2026-10-18 10:01:00,203.0.113.15,admin,FAILED",
            "2026-10-18 10:02:00,203.0.113.15,admin,FAILED",
            "2026-10-18 10:03:00,203.0.113.15,admin,FAILED",
            "2026-10-18 10:04:00,203.0.113.15,admin,FAILED"
        ])

        with tempfile.TemporaryDirectory() as temp_dir:

            log_file = Path(temp_dir) / "test_logs.txt"

            log_file.write_text(
                log_content,
                encoding="utf-8"
            )

            result = analyze_log_file(
                str(log_file),
                window_minutes=10
            )

        self.assertEqual(
            result,
            {"203.0.113.15": 5}
        )
    
    def test_ignores_attempts_outside_window(self):

        log_content = "\n".join([
            "2026-10-18 10:00:00,203.0.113.15,admin,FAILED",
            "2026-10-18 10:01:00,203.0.113.15,admin,FAILED",
            "2026-10-18 10:02:00,203.0.113.15,admin,FAILED",
            "2026-10-18 10:20:00,203.0.113.15,admin,FAILED",
            "2026-10-18 10:21:00,203.0.113.15,admin,FAILED"
        ])

        with tempfile.TemporaryDirectory() as temp_dir:

            log_file = Path(temp_dir) / "test_logs.txt"

            log_file.write_text(
                log_content,
                encoding="utf-8"
            )

            result = analyze_log_file(
                str(log_file),
                window_minutes=10
            )

        self.assertEqual(
            result,
            {"203.0.113.15": 3}
        )
    def test_successful_logins_are_ignored(self):

        log_content = "\n".join([
            "2026-10-18 10:00:00,203.0.113.15,admin,FAILED",
            "2026-10-18 10:01:00,203.0.113.15,admin,SUCCESS",
            "2026-10-18 10:02:00,203.0.113.15,admin,FAILED",
            "2026-10-18 10:03:00,203.0.113.15,admin,SUCCESS",
            "2026-10-18 10:04:00,203.0.113.15,admin,FAILED",
            "2026-10-18 10:05:00,203.0.113.15,admin,SUCCESS",
            "2026-10-18 10:06:00,203.0.113.15,admin,FAILED"
        ])

        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "test_logs.txt"

            log_file.write_text(log_content, encoding="utf-8")

            result = analyze_log_file(str(log_file), window_minutes=10)

        self.assertEqual(result, {"203.0.113.15": 4})


if __name__ == "__main__":
    unittest.main()

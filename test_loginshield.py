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
    def test_invalid_status(self):
        line = "2026-10-18 10:00:12,192.0.2.10,alice,PENDING"

        result = parse_log_line(line)

        self.assertIsNone(result)
    def test_missing_fields(self):
        line = "2026-10-18 10:00:12,192.0.2.10,alice"

        result = parse_log_line(line)

        self.assertIsNone(result)
if __name__ == "__main__":
    unittest.main()
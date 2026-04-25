import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from prompt_firewall.cli import (
    active_detectors,
    find_matches,
    luhn_valid,
    main,
    redact,
)


class PromptFirewallTests(unittest.TestCase):
    def test_redacts_email_and_secret_assignment(self):
        text = "email me at test@example.com\napi_key=super-secret"

        redacted = redact(text)

        self.assertIn("[email_REDACTED]", redacted)
        self.assertIn("[secret_assignment_REDACTED]", redacted)
        self.assertNotIn("test@example.com", redacted)
        self.assertNotIn("super-secret", redacted)

    def test_scan_reports_line_numbers_without_raw_values(self):
        findings = find_matches("hello\ncontact me@example.com")

        self.assertEqual(findings[0]["type"], "email")
        self.assertEqual(findings[0]["line"], 2)
        self.assertEqual(findings[0]["preview"], "me@...com")

    def test_credit_card_uses_luhn_check(self):
        self.assertTrue(luhn_valid("4242 4242 4242 4242"))
        self.assertFalse(luhn_valid("1234 5678 9012 3456"))

        findings = find_matches("card 4242 4242 4242 4242 not 1234 5678 9012 3456")

        self.assertEqual([finding["type"] for finding in findings], ["credit_card"])

    def test_can_limit_detectors(self):
        detectors = active_detectors(["email"])
        text = "test@example.com token=abc123"

        self.assertEqual(redact(text, detectors), "[email_REDACTED] token=abc123")

    def test_cli_defaults_to_redact_from_stdin(self):
        with patch("sys.argv", ["prompt-firewall"]), patch(
            "sys.stdin", io.StringIO("test@example.com")
        ), redirect_stdout(io.StringIO()) as output:
            main()

        self.assertEqual(output.getvalue().strip(), "[email_REDACTED]")

    def test_fail_on_detect_exits_nonzero(self):
        with patch(
            "sys.argv",
            ["prompt-firewall", "scan", "--fail-on-detect"],
        ), patch("sys.stdin", io.StringIO("test@example.com")):
            with self.assertRaises(SystemExit) as error:
                main()

        self.assertEqual(error.exception.code, 1)


if __name__ == "__main__":
    unittest.main()

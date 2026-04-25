import unittest
from prompt_firewall.cli import redact

class Tests(unittest.TestCase):
    def test_redacts_email(self):
        self.assertIn('[EMAIL_REDACTED]', redact('a@b.com'))

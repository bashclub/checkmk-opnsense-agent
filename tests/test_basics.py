import re
import subprocess
import sys
import unittest

from harness import AGENT_PATH, FakeOPNsense, load_agent


class TestSource(unittest.TestCase):
    def test_compiles_without_syntax_warnings(self):
        """#77: invalid escape sequences produce SyntaxWarnings with newer Python versions."""
        result = subprocess.run(
            [sys.executable, "-W", "error::SyntaxWarning", "-c",
             "import sys; compile(open(sys.argv[1], encoding='utf-8').read(), sys.argv[1], 'exec')", str(AGENT_PATH)],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_short_help_option(self):
        """#61: -h must work as well as --help."""
        self.assertRegex(AGENT_PATH.read_text(encoding="utf-8"), r'add_argument\("-h","--help"')

    def test_agent_imports(self):
        agent = load_agent()
        self.assertTrue(re.match(r"^\d+\.\d+\.\d+$", agent.__VERSION__))


class TestCertificates(unittest.TestCase):
    def test_single_certificate_in_store(self):
        """#55: with only one certificate config.xml has a dict instead of a list."""
        from certs import cert_xml
        from harness import config_xml
        with FakeOPNsense(config_xml(cert_xml("abc123", "fw.example.org"))) as checker:
            cert = checker._get_certificate("abc123")
        self.assertEqual(cert.get("common_name"), "fw.example.org")
        self.assertGreater(cert.get("not_valid_after"), 0)

    @unittest.expectedFailure  # _certificate_parser calls .get() on None when config.xml has no <cert> at all
    def test_no_certificate_in_store(self):
        from harness import config_xml
        with FakeOPNsense(config_xml("")) as checker:
            self.assertIsNone(checker._get_certificate("missing"))


if __name__ == "__main__":
    unittest.main()

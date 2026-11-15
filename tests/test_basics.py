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

    def test_no_certificate_in_store(self):
        """_certificate_parser called .get() on None when config.xml has no <cert> at all."""
        from harness import config_xml
        with FakeOPNsense(config_xml("")) as checker:
            self.assertIsNone(checker._get_certificate("missing"))



class TestSpool(unittest.TestCase):
    def test_max_age_prefix(self):
        """"600_name" is only delivered for 600s; the prefix was matched against the full path and never worked."""
        import os
        import tempfile
        import time
        agent = load_agent()
        with tempfile.TemporaryDirectory() as spooldir:
            for name, age in (("plain", 99999), ("600_fresh", 60), ("600_old", 3600)):
                path = os.path.join(spooldir, name)
                with open(path, "w") as f:
                    f.write(f"<<<local:sep(0)>>>\n0 {name} - ok\n")
                os.utime(path, (time.time() - age, time.time() - age))
            os.mkdir(os.path.join(spooldir, "subdir"))
            content = "".join(agent.checkmk_checker._read_spool(spooldir))
        self.assertIn("0 plain - ok", content)
        self.assertIn("0 600_fresh - ok", content)
        self.assertNotIn("600_old", content)


if __name__ == "__main__":
    unittest.main()

"""Local check "Checkmk Agent Update": compares the own version with release (main) and testing on code.bashclub.org."""
import unittest
from unittest import mock

from harness import FakeOPNsense, load_agent

NOW = 1_795_000_000


class TestAgentUpdate(unittest.TestCase):
    def run_check(self, current, versions, now=NOW, checker=None):
        """versions: {"main": "1.2.17" | Exception, "testing": ...}"""
        calls = []

        def fetch(branch):
            calls.append(branch)
            value = versions.get(branch, ValueError("HTTP 404"))
            if isinstance(value, Exception):
                raise value
            return value

        agent = load_agent()
        with mock.patch.object(agent, "__VERSION__", current):
            with FakeOPNsense(now=now) as fake_checker:
                checker = checker or fake_checker
                with mock.patch.object(checker, "_fetch_agent_version", side_effect=fetch):
                    line = checker.checklocal_agentupdate()[0]
        return line, calls

    def test_up_to_date(self):
        line, _ = self.run_check("1.2.17", {"main": "1.2.17", "testing": "1.2.17"})
        self.assertEqual(line, '0 "Checkmk Agent Update" update_available=0 Version 1.2.17 is up to date '
                               '(release 1.2.17, testing 1.2.17)')

    def test_release_update_available(self):
        line, _ = self.run_check("1.2.16", {"main": "1.2.17", "testing": "1.2.18"})
        self.assertTrue(line.startswith('1 "Checkmk Agent Update" update_available=1 Version 1.2.16, update to 1.2.17'), line)

    def test_version_compare_is_numeric(self):
        line, _ = self.run_check("1.2.9", {"main": "1.2.10"})
        self.assertTrue(line.startswith("1 "), line)

    def test_testing_version_newer_than_release(self):
        line, _ = self.run_check("1.2.18", {"main": "1.2.17", "testing": "1.2.18"})
        self.assertTrue(line.startswith("0 ") and "1.2.18 (testing) is up to date" in line, line)

    def test_testing_update_available(self):
        line, _ = self.run_check("1.2.18", {"main": "1.2.17", "testing": "1.2.19"})
        self.assertTrue(line.startswith("1 ") and "update to testing 1.2.19" in line, line)

    def test_release_user_is_not_warned_about_testing(self):
        line, _ = self.run_check("1.2.17", {"main": "1.2.17", "testing": "1.2.19"})
        self.assertTrue(line.startswith("0 "), line)

    def test_no_internet(self):
        """air-gapped: OK with a note, never WARN/CRIT."""
        line, _ = self.run_check("1.2.17", {"main": ConnectionError("Name does not resolve"),
                                            "testing": ConnectionError("Name does not resolve")})
        self.assertEqual(line, '0 "Checkmk Agent Update" update_available=0 Version 1.2.17, '
                               'update check not possible: Name does not resolve')

    def test_missing_testing_branch_is_ignored(self):
        line, _ = self.run_check("1.2.17", {"main": "1.2.17"})
        self.assertEqual(line, '0 "Checkmk Agent Update" update_available=0 Version 1.2.17 is up to date (release 1.2.17)')

    def test_checks_only_once_a_day(self):
        agent = load_agent()
        versions = {"main": "1.2.17", "testing": "1.2.17"}
        fetched = []
        with mock.patch.object(agent, "__VERSION__", "1.2.17"), FakeOPNsense() as checker:
            with mock.patch.object(checker, "_fetch_agent_version", side_effect=lambda b: fetched.append(b) or versions[b]):
                for now, expected_calls in ((NOW, 2), (NOW + 3600, 2), (NOW + 86400 + 1, 4)):
                    with mock.patch.object(agent.time, "time", return_value=now):
                        checker.checklocal_agentupdate()
                    self.assertEqual(len(fetched), expected_calls, f"at +{now - NOW}s")

    def test_retry_after_an_hour_on_error_and_keep_known_versions(self):
        agent = load_agent()
        state = {"fail": False}

        def fetch(branch):
            if state["fail"]:
                raise ConnectionError("timeout")
            return "1.2.18"

        with mock.patch.object(agent, "__VERSION__", "1.2.17"), FakeOPNsense() as checker:
            with mock.patch.object(checker, "_fetch_agent_version", side_effect=fetch) as fetch_mock:
                with mock.patch.object(agent.time, "time", return_value=NOW):
                    checker.checklocal_agentupdate()
                state["fail"] = True
                with mock.patch.object(agent.time, "time", return_value=NOW + 86400 + 1):
                    line = checker.checklocal_agentupdate()[0]
                self.assertTrue(line.startswith("1 ") and "update to 1.2.18" in line and "last check failed: timeout" in line, line)
                calls = fetch_mock.call_count
                with mock.patch.object(agent.time, "time", return_value=NOW + 86400 + 1800):
                    checker.checklocal_agentupdate()
                self.assertEqual(fetch_mock.call_count, calls, "no new request within the hour after an error")
                with mock.patch.object(agent.time, "time", return_value=NOW + 86400 + 3602):
                    checker.checklocal_agentupdate()
                self.assertGreater(fetch_mock.call_count, calls)


class TestFetchAgentVersion(unittest.TestCase):
    def fake_response(self, status, chunks):
        response = mock.Mock(status_code=status)
        response.iter_content.return_value = iter(chunks)
        return response

    def test_reads_version_from_the_head_of_the_file(self):
        agent = load_agent()
        response = self.fake_response(200, [b"#!/usr/bin/env python3\n## comment\n__VERSION__ ", b'= "1.2.20"\n\nimport sys\n'])
        with mock.patch.object(agent.requests, "get", return_value=response) as get:
            self.assertEqual(agent.checkmk_checker._fetch_agent_version("testing"), "1.2.20")
        self.assertEqual(get.call_args.args[0],
                         "https://code.bashclub.org/bashclub/checkmk-opnsense-agent/raw/branch/testing/opnsense_checkmk_agent.py")
        self.assertEqual(get.call_args.kwargs.get("timeout"), 5)
        # code.bashclub.org answers "python-requests/..." with 403 (bad-bot filter)
        user_agent = get.call_args.kwargs.get("headers", {}).get("User-Agent", "")
        self.assertTrue(user_agent.startswith("checkmk-opnsense-agent/"), user_agent)
        response.close.assert_called_once()

    def test_http_error(self):
        agent = load_agent()
        with mock.patch.object(agent.requests, "get", return_value=self.fake_response(404, [])):
            with self.assertRaisesRegex(ValueError, "HTTP 404"):
                agent.checkmk_checker._fetch_agent_version("main")

    def test_own_version_is_found_by_the_same_pattern(self):
        """the check reads the version of the published file exactly like this one."""
        from harness import AGENT_PATH
        agent = load_agent()
        head = AGENT_PATH.read_bytes()[:65536]
        response = self.fake_response(200, [head[i:i + 4096] for i in range(0, len(head), 4096)])
        with mock.patch.object(agent.requests, "get", return_value=response):
            self.assertEqual(agent.checkmk_checker._fetch_agent_version("main"), agent.__VERSION__)


if __name__ == "__main__":
    unittest.main()

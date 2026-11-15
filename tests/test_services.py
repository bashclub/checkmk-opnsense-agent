"""Local check "Services": OPNsense services (System > Diagnostics > Services), option skipservice (idea from PR #70)."""
import unittest
from unittest import mock

from harness import FakeOPNsense, load_agent

SERVICES = [("unbound", "Unbound DNS", True), ("ntpd", "Network Time Daemon", True),
            ("ntopng", "ntopng", False), ("haproxy", "HAProxy Load Balancer", False)]


def run_services(services=SERVICES, skipservice=()):
    with FakeOPNsense() as checker:
        checker.skipservice = list(skipservice)
        with mock.patch.object(checker, "_get_opnsense_services", return_value=services):
            return checker.checklocal_services()[0]


class TestServices(unittest.TestCase):
    def test_all_running(self):
        line = run_services(SERVICES[:2])
        self.assertEqual(line, "0 Services running_services=2|stopped_service=0 All Services running")

    def test_stopped_is_crit(self):
        line = run_services()
        self.assertEqual(line, "2 Services running_services=2|stopped_service=2 "
                               "Services: ntopng, HAProxy Load Balancer not running")

    def test_skipped_services_by_name_and_description(self):
        line = run_services(skipservice=["ntopng", "haproxy load balancer"])
        self.assertEqual(line, "0 Services running_services=2|stopped_service=0 All Services running "
                               "(stopped, ignored: ntopng, HAProxy Load Balancer)")

    def test_skip_only_one(self):
        line = run_services(skipservice=["ntopng"])
        self.assertTrue(line.startswith("2 Services running_services=2|stopped_service=1 "), line)
        self.assertIn("HAProxy Load Balancer not running (stopped, ignored: ntopng)", line)

    def test_skipped_but_running_is_not_mentioned(self):
        line = run_services(SERVICES[:2], skipservice=["unbound"])
        self.assertEqual(line, "0 Services running_services=2|stopped_service=0 All Services running")


class TestGetServices(unittest.TestCase):
    def test_parse_php_output(self):
        agent = load_agent()
        process = mock.Mock()
        process.communicate.return_value = ("unbound;Unbound DNS;1\nntopng;ntopng;0\n\nbroken line\n", None)
        with mock.patch.object(agent.subprocess, "Popen", return_value=process):
            services = agent.checkmk_checker._get_opnsense_services()
        self.assertEqual(services, [("unbound", "Unbound DNS", True), ("ntopng", "ntopng", False)])

    def test_no_output(self):
        agent = load_agent()
        process = mock.Mock()
        process.communicate.return_value = ("", None)
        with mock.patch.object(agent.subprocess, "Popen", return_value=process):
            self.assertEqual(agent.checkmk_checker._get_opnsense_services(), [])


class TestOptions(unittest.TestCase):
    def make_server(self, **options):
        agent = load_agent()
        with mock.patch.object(agent.checkmk_checker, "_run_prog", return_value=""):
            server = agent.checkmk_server(port=0, pidfile="/nonexistent/checkmk_agent.pid", **options)
        server.server_close()
        return server

    def test_skipservice_is_lower_case_list(self):
        server = self.make_server(skipservice="ntopng, HAProxy Load Balancer,")
        self.assertEqual(server.skipservice, ["ntopng", "haproxy load balancer"])

    def test_skipcheck_with_spaces(self):
        """"skipcheck: ipmi, agentupdate" did not skip agentupdate (leading space)."""
        server = self.make_server(skipcheck="ipmi, agentupdate")
        self.assertEqual(server.skipcheck, ["ipmi", "agentupdate"])


if __name__ == "__main__":
    unittest.main()

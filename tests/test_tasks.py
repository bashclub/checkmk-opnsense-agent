"""Tasks (/usr/local/check_mk_agent/tasks/*.task): service "CMK Tasks" and the blocklist task."""
import unittest
from unittest import mock

from harness import load_agent


def runner_with(agent, *tasks):
    runner = agent.checkmk_taskrunner(None)
    runner._queue.extend(tasks)
    return runner


class TestTaskRunner(unittest.TestCase):
    def test_service_has_own_section_and_double_quotes(self):
        """'CMK Tasks' in single quotes and without section header ended up in the section before it."""
        agent = load_agent()
        task = agent.checkmk_task("dummy.task", {"type": "dummy", "interval": "60"})
        task._data = task._dummy()
        with mock.patch.object(agent.sys, "stderr"):
            lines = runner_with(agent, task).get_data()
        self.assertEqual(lines[0], "<<<local:sep(0)>>>")
        self.assertEqual(lines[1], '0 "CMK Tasks" tasks=1|tasks_running=0|tasks_failed=0 OK')
        self.assertIn("0 Dummy - Test", "\n".join(lines))

    def test_tenant_gets_only_its_tasks(self):
        agent = load_agent()
        own = agent.checkmk_task("own.task", {"type": "dummy", "tenant": "192.0.2.20"})
        other = agent.checkmk_task("other.task", {"type": "cmk"})
        own._data, other._data = "OWN-DATA", "SHARED-DATA"
        hidden = agent.checkmk_task("hidden.task", {"type": "dummy", "tenant": "192.0.2.21"})
        hidden._data = "HIDDEN-DATA"
        with mock.patch.object(agent.sys, "stderr"):
            lines = runner_with(agent, own, other, hidden).get_data(tenant="192.0.2.20")
        self.assertIn("OWN-DATA", lines)
        self.assertIn("SHARED-DATA", lines)
        self.assertNotIn("HIDDEN-DATA", lines)

    def test_no_tasks(self):
        agent = load_agent()
        self.assertEqual(runner_with(agent).get_data(), [])


class FakeResolver:
    """192.0.2.66 is listed on every blocklist, the A record of mail.example.org is 192.0.2.10."""

    def dns_reverseip(self, ip, tld=False):
        return ".".join(reversed(ip.split(".")))

    def resolve(self, hostname, rrtype="A", secure=True):
        if rrtype == "A" and hostname == "mail.example.org":
            return False, ["192.0.2.10"]
        return False, ["127.0.0.2"] if hostname.startswith("66.2.0.192.") else []


class TestBlocklist(unittest.TestCase):
    def run_task(self, config):
        agent = load_agent()
        task = agent.checkmk_task("bl.task", dict(config, type="blocklist"))
        with mock.patch.object(agent, "checkmk_resolver", FakeResolver):
            return task._blocklist().splitlines()[1], len(agent.BLACKLISTS)

    def test_not_listed_by_hostname(self):
        """with a hostname, the resolved addresses were consumed twice (map object) and the text was empty."""
        line, count = self.run_task({"hostname": "mail.example.org"})
        self.assertEqual(line.split(" ", 1)[1], f'0 "Blocklist mail.example.org" blocklist={count}|blocked=0 192.0.2.10 not blocked')

    def test_listed(self):
        line, count = self.run_task({"ipaddress": "192.0.2.66, 192.0.2.10", "service": "WAN"})
        self.assertTrue(line.split(" ", 1)[1].startswith(f'2 "Blocklist WAN" blocklist={count}|blocked={count} '), line)
        self.assertIn("192.0.2.66 is on", line)


if __name__ == "__main__":
    unittest.main()

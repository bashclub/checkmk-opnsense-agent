"""Access control: onlyfrom and tenants with the dual-stack socket (IPv4 clients arrive as ::ffff:a.b.c.d)."""
import unittest
from unittest import mock

from harness import load_agent


def make_server(agent, **options):
    with mock.patch.object(agent.checkmk_checker, "_run_prog", return_value=""):
        server = agent.checkmk_server(port=0, pidfile="/nonexistent/checkmk_agent.pid", **options)
    server.server_close()
    return server


class TestClientIp(unittest.TestCase):
    def test_normalize(self):
        agent = load_agent()
        for given, expected in (("::ffff:192.0.2.10", "192.0.2.10"), ("192.0.2.10", "192.0.2.10"),
                                ("2001:db8::10", "2001:db8::10"), ("2001:DB8:0::0010", "2001:db8::10"),
                                (" 192.0.2.10 ", "192.0.2.10"), ("checkmk", None), ("192.0.2.0/24", None), ("", None)):
            self.assertEqual(agent.client_ip(given), expected, given)


class TestOnlyFrom(unittest.TestCase):
    def allowed(self, client, **options):
        agent = load_agent()
        with mock.patch.object(agent, "log") as log:
            server = make_server(agent, **options)
            self.log = [call.args[0] for call in log.call_args_list]
            return server.verify_request(None, (client, 40000, 0, 0))

    def test_ipv4_client_on_dual_stack_socket(self):
        """since 1.2.11 every IPv4 client was rejected when onlyfrom was set (found while writing the handbook)."""
        self.assertTrue(self.allowed("::ffff:192.0.2.10", onlyfrom="192.0.2.10"))

    def test_other_client_is_rejected(self):
        self.assertFalse(self.allowed("::ffff:192.0.2.99", onlyfrom="192.0.2.10,192.0.2.11"))

    def test_ipv6_client(self):
        self.assertTrue(self.allowed("2001:db8::10", onlyfrom="192.0.2.10, 2001:db8::10"))

    def test_mapped_notation_in_config_keeps_working(self):
        """the workaround some users found: onlyfrom: ::ffff:192.0.2.10"""
        self.assertTrue(self.allowed("::ffff:192.0.2.10", onlyfrom="::ffff:192.0.2.10"))

    def test_ipv6_written_differently(self):
        self.assertTrue(self.allowed("2001:db8::10", onlyfrom="2001:DB8:0:0::10"))

    def test_invalid_entries_are_ignored_and_logged(self):
        self.assertTrue(self.allowed("::ffff:192.0.2.10", onlyfrom="checkmk.example.org,192.0.2.10"))
        self.assertFalse(self.allowed("::ffff:192.0.2.99", onlyfrom="checkmk.example.org,192.0.2.10"))
        self.assertIn("onlyfrom: ignoring 'checkmk.example.org', only IPv4 and IPv6 addresses are allowed", self.log)

    def test_networks_are_not_supported(self):
        self.assertFalse(self.allowed("::ffff:192.0.2.10", onlyfrom="192.0.2.0/24"))

    def test_without_valid_address_nobody(self):
        """fail closed: "onlyfrom:" set but empty, only commas or only invalid entries rejects everybody."""
        for value in ("", ",", " , ", "checkmk.example.org"):
            self.assertFalse(self.allowed("::ffff:192.0.2.10", onlyfrom=value), repr(value))
        self.assertIn("onlyfrom contains no valid address, all connections are rejected", self.log)

    def test_without_onlyfrom_everybody(self):
        self.assertTrue(self.allowed("::ffff:198.51.100.1"))

    def test_tenant_is_allowed(self):
        self.assertTrue(self.allowed("::ffff:192.0.2.20", onlyfrom="192.0.2.10", tenants="192.0.2.20#secret"))


class TestTenants(unittest.TestCase):
    def test_with_and_without_secret(self):
        """a tenant without "#secret" raised NameError and stopped the agent."""
        agent = load_agent()
        with mock.patch.object(agent, "log"):
            server = make_server(agent, tenants="192.0.2.20#secret,192.0.2.21,192.0.2.22#,kunde.example.org#x")
        self.assertEqual(server.tenants, {"192.0.2.20": "secret", "192.0.2.21": None, "192.0.2.22": None})


if __name__ == "__main__":
    unittest.main()

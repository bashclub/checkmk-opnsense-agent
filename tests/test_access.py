"""Access control: onlyfrom and tenants with the dual-stack socket (IPv4 clients arrive as ::ffff:a.b.c.d)."""
import os
import tempfile
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
        self.assertIn("onlyfrom: ignoring 'checkmk.example.org', only IPv4/IPv6 addresses and networks are allowed", self.log)

    def test_networks(self):
        """onlyfrom with networks (CIDR), IPv4 and IPv6."""
        self.assertTrue(self.allowed("::ffff:192.0.2.10", onlyfrom="192.0.2.0/24"))
        self.assertTrue(self.allowed("::ffff:192.0.2.10", onlyfrom="192.0.2.17/24"))  # host bits are ignored
        self.assertFalse(self.allowed("::ffff:192.0.3.10", onlyfrom="192.0.2.0/24"))
        self.assertTrue(self.allowed("2001:db8:1::5", onlyfrom="198.51.100.1,2001:db8:1::/48"))
        self.assertFalse(self.allowed("2001:db8:2::5", onlyfrom="2001:db8:1::/48"))

    def test_invalid_network_is_ignored(self):
        self.assertFalse(self.allowed("::ffff:192.0.2.10", onlyfrom="192.0.2.0/33"))
        self.assertIn("onlyfrom: ignoring '192.0.2.0/33', only IPv4/IPv6 addresses and networks are allowed", self.log)

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


class TestConfigFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "checkmk.conf")

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, text, mtime):
        with open(self.path, "w") as f:
            f.write(text)
        os.utime(self.path, (mtime, mtime))

    def test_read_config(self):
        """feedback Marc Risse: "skipservice ntpd" (without colon) was ignored silently."""
        agent = load_agent()
        self.write("# comment\nskipservice ntpd\nSkipCheck: ipmi  # no ipmi\nfoo: bar\nonlyfrom: 192.0.2.10\nbroken line\n", 1000)
        with mock.patch.object(agent, "log") as log:
            options = agent.read_config(self.path)
        self.assertEqual(options, {"skipservice": "ntpd", "skipcheck": "ipmi", "onlyfrom": "192.0.2.10"})
        messages = [call.args[0] for call in log.call_args_list]
        self.assertIn(f"{self.path} line 2: colon missing, read as 'skipservice: ntpd'", messages)
        self.assertIn(f"{self.path} line 6 ignored, expected 'name: value': broken line", messages)
        self.assertIn(f"{self.path} line 4: unknown option 'foo'", messages)

    def test_running_daemon_applies_changes(self):
        """feedback Marc Risse: a changed checkmk.conf needed a restart."""
        agent = load_agent()
        self.write("skipservice: ntpd\n", 1000)
        with mock.patch.object(agent, "log"):
            server = make_server(agent, skipservice="ntpd", configfile=self.path, cli_options={})
            self.assertTrue(server.verify_request(None, ("::ffff:192.0.2.99", 1, 0, 0)))
            self.write("skipservice: ntpd, HAProxy\nonlyfrom: 192.0.2.10\n", 2000)
            self.assertFalse(server.verify_request(None, ("::ffff:192.0.2.99", 1, 0, 0)))
            self.assertTrue(server.verify_request(None, ("::ffff:192.0.2.10", 1, 0, 0)))
            self.assertEqual(server.skipservice, ["ntpd", "haproxy"])
            self.write("# all removed\n", 3000)  # back to the command line options
            self.assertTrue(server.verify_request(None, ("::ffff:192.0.2.99", 1, 0, 0)))
            self.assertEqual(server.skipservice, [])

    def test_netbird_idle_option(self):
        agent = load_agent()
        with mock.patch.object(agent, "log") as log:
            self.assertEqual(make_server(agent, netbird_idle="WARN").netbird_idle, "warn")
            self.assertEqual(make_server(agent, netbird_idle="sometimes").netbird_idle, "ok")
            self.assertEqual(make_server(agent).netbird_idle, "ok")
        self.assertIn("netbird_idle: 'sometimes' unknown, use ok, warn or crit", [c.args[0] for c in log.call_args_list])

    def test_encrypt_from_command_line_wins(self):
        agent = load_agent()
        self.write("encrypt: from-file\n", 1000)
        with mock.patch.object(agent, "log"):
            server = make_server(agent, encrypt="from-cli", configfile=self.path, cli_options={"encrypt": "from-cli"})
            self.write("encrypt: changed\n", 2000)
            server.verify_request(None, ("::ffff:192.0.2.99", 1, 0, 0))
        self.assertEqual(server.encrypt, "from-cli")

    def test_without_config_file(self):
        agent = load_agent()
        with mock.patch.object(agent, "log"):
            server = make_server(agent, skipcheck="ipmi", configfile=self.path, cli_options={"skipcheck": "ipmi"})
            self.assertTrue(server.verify_request(None, ("::ffff:192.0.2.99", 1, 0, 0)))
        self.assertEqual(server.skipcheck, ["ipmi"])


if __name__ == "__main__":
    unittest.main()

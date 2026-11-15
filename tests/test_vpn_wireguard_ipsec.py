import json
import unittest

from harness import FakeOPNsense, config_xml, fixture, local_lines

NOW = 1_790_000_000

WG_CONFIG = config_xml("""
<OPNsense><wireguard>
  <server><servers>
    <server uuid="s1"><enabled>1</enabled><instance>0</instance><name>wg-site</name><peers>c1,c2</peers></server>
  </servers></server>
  <client><clients>
    <client uuid="c1"><enabled>1</enabled><name>site-a</name><pubkey>PUBKEY_A=</pubkey>
      <tunneladdress>10.0.0.0/24</tunneladdress><serveraddress>203.0.113.10</serveraddress></client>
    <client uuid="c2"><enabled>1</enabled><name>phone</name><pubkey>PUBKEY_B=</pubkey>
      <tunneladdress>10.0.1.2/32</tunneladdress><serveraddress/></client>
  </clients></client>
</wireguard></OPNsense>
""")


def wg_dump(handshake_a, handshake_b):
    return "\n".join([
        "wg0\tPRIVKEY=\tSERVERPUB=\t51820\toff",
        f"wg0\tPUBKEY_A=\t(none)\t203.0.113.10:51820\t10.0.0.0/24\t{handshake_a}\t1000\t2000\t25",
        f"wg0\tPUBKEY_B=\t(none)\t198.51.100.8:40000\t10.0.1.2/32\t{handshake_b}\t300\t400\toff",
    ]) + "\n"


class TestWireGuard(unittest.TestCase):
    def run_check(self, handshake_a, handshake_b):
        with FakeOPNsense(WG_CONFIG, commands={"wg show all dump": wg_dump(handshake_a, handshake_b)}, now=NOW) as checker:
            return checker.checklocal_wireguard()

    def test_connected_peers(self):
        lines = self.run_check(NOW - 30, NOW - 60)
        self.assertEqual(len(lines), 2, lines)
        self.assertTrue(all(l.startswith("0 ") for l in lines), lines)
        self.assertIn('"WireGuard Client: site-a"', lines[0])
        self.assertIn("wg0: online, IP:203.0.113.10 - 10.0.0.0/24", lines[0])

    def test_site_to_site_peer_down(self):
        lines = self.run_check(NOW - 3600, NOW - 60)
        site = local_lines(lines, "WireGuard Client: site-a")[0]
        self.assertTrue(site.startswith("2 "), site)
        self.assertIn("offline, last handshake 1h 0m ago, last IP:203.0.113.10", site)

    def test_roadwarrior_offline_is_ok(self):
        """#52 / #39, PR #85: a roadwarrior without endpoint address is offline most of the time."""
        lines = self.run_check(NOW - 30, NOW - 4 * 3600)
        phone = local_lines(lines, "WireGuard Client: phone")[0]
        self.assertTrue(phone.startswith("0 "), phone)
        self.assertIn("wg0: offline, last handshake 4h 0m ago, last IP:198.51.100.8", phone)

    def test_roadwarrior_never_connected(self):
        lines = self.run_check(NOW - 30, 0)
        phone = local_lines(lines, "WireGuard Client: phone")[0]
        self.assertTrue(phone.startswith("0 ") and "offline, no handshake since start" in phone, phone)

    def test_roadwarrior_online(self):
        lines = self.run_check(NOW - 30, NOW - 120)
        phone = local_lines(lines, "WireGuard Client: phone")[0]
        self.assertTrue(phone.startswith("0 ") and "online, IP:198.51.100.8" in phone, phone)

    def test_instance_down_is_crit(self):
        """enabled peers missing in "wg show" (instance not running) are CRIT, also roadwarriors."""
        with FakeOPNsense(WG_CONFIG, commands={"wg show all dump": ""}, now=NOW) as checker:
            lines = checker.checklocal_wireguard()
        self.assertEqual(len(lines), 2, lines)
        self.assertTrue(all(l.startswith("2 ") and "wg0: peer not loaded" in l for l in lines), lines)

    def test_disabled_peer_and_instance_are_skipped(self):
        config = (WG_CONFIG.replace("<enabled>1</enabled><name>phone</name>", "<enabled>0</enabled><name>phone</name>")
                  .replace("</servers>", '<server uuid="s2"><enabled>0</enabled><instance>1</instance>'
                                         "<name>off</name><peers>c3</peers></server></servers>")
                  .replace("</clients>", '<client uuid="c3"><enabled>1</enabled><name>old</name><pubkey>PUBKEY_C=</pubkey>'
                                         "<tunneladdress>10.0.2.2/32</tunneladdress><serveraddress/></client></clients>"))
        with FakeOPNsense(config, commands={"wg show all dump": wg_dump(NOW - 30, NOW - 30)}, now=NOW) as checker:
            lines = checker.checklocal_wireguard()
        self.assertEqual([l.split('"')[1] for l in lines], ["WireGuard Client: site-a"], lines)


IPSEC_LEGACY = config_xml("""
<ipsec>
  <enable>1</enable>
  <phase1><ikeid>1</ikeid><descr>{descr}</descr><remote-gateway>192.0.2.50</remote-gateway></phase1>
  <phase2><ikeid>1</ikeid><uniqid>p2a</uniqid></phase2>
</ipsec>
""")
IPSEC_STATUS = {"con1": {"local-id": "198.51.100.1", "remote-id": "192.0.2.50", "sas": [{
    "state": "ESTABLISHED", "local-id": "198.51.100.1", "remote-id": "192.0.2.50", "remote-host": "192.0.2.50",
    "child-sas": {"con1-1": {"state": "INSTALLED", "install-time": "100", "bytes-in": "10000", "bytes-out": "20000"}},
}]}}


class TestIPsecLegacy(unittest.TestCase):
    def run_check(self, descr):
        commands = {"/usr/local/opnsense/scripts/ipsec/list_status.py": json.dumps(IPSEC_STATUS)}
        with FakeOPNsense(IPSEC_LEGACY.format(descr=descr), commands=commands, now=NOW) as checker:
            return checker.checklocal_ipsec()

    def test_tunnel_up(self):
        lines = self.run_check("Branch")
        self.assertEqual(len(lines), 1, lines)
        self.assertTrue(lines[0].startswith('0 "IPsec Tunnel: Branch"'), lines[0])

    def test_tunnel_without_description(self):
        """#34: a phase 1 without description stopped the check (None.strip())."""
        lines = self.run_check("")
        self.assertTrue(lines[0].startswith('0 "IPsec Tunnel: 192.0.2.50"'), lines)


# real data from the test VM (OPNsense 26.7.9, strongSwan 6.1): tests/fixtures/ipsec-26.7
LIST_STATUS = "/usr/local/opnsense/scripts/ipsec/list_status.py"
LOOP_A, LOOP_B = "aaaaaaaa-0000-4000-8000-000000000001", "bbbbbbbb-0000-4000-8000-000000000002"


def vm_status(with_children=False):
    status = json.loads(fixture("ipsec-26.7", "status.json"))
    if with_children:
        for conn, child_sas in json.loads(fixture("ipsec-26.7", "children.json")).items():
            if not conn.startswith("_"):
                status[conn]["sas"][0]["child-sas"] = child_sas
    return json.dumps(status)


def vm_ipsec(status, config=None):
    config = config_xml(config or fixture("ipsec-26.7", "config.xml"))
    with FakeOPNsense(config, commands={LIST_STATUS: status}, now=NOW) as checker:
        return checker.checklocal_ipsec()


def by_name(lines):
    return {l.split('"')[1]: l for l in lines}


class TestIPsecRealVM(unittest.TestCase):
    def test_established_without_children(self):
        """IKE up, but no CHILD_SA: not connected (real VM state)."""
        lines = by_name(vm_ipsec(vm_status()))
        self.assertEqual(sorted(lines), ["IPsec Tunnel: 192.0.2.50", "IPsec Tunnel: Loop A", "IPsec Tunnel: Loop B",
                                         "IPsec Tunnel: Nowhere"])
        self.assertTrue(lines["IPsec Tunnel: Loop A"].startswith("2 "), lines)
        self.assertIn("not connected (ESTABLISHED) a.loop - b.loop(127.0.0.1)", lines["IPsec Tunnel: Loop A"])
        self.assertIn("not connected (CONNECTING)", lines["IPsec Tunnel: Nowhere"])
        self.assertIn("not running", lines["IPsec Tunnel: 192.0.2.50"])  # legacy, not loaded

    def test_children_up(self):
        lines = by_name(vm_ipsec(vm_status(with_children=True)))
        self.assertTrue(lines["IPsec Tunnel: Loop B"].startswith("0 "), lines)
        self.assertIn("if_in_octets=2000|if_out_octets=1000|lifetime=600 ESTABLISHED b.loop - a.loop(10.91.0.185)",
                      lines["IPsec Tunnel: Loop B"])
        self.assertTrue(lines["IPsec Tunnel: Loop A"].startswith("1 "), lines)
        self.assertIn("1/2 children up, down: Loop A unmatched", lines["IPsec Tunnel: Loop A"])
        self.assertTrue(lines["IPsec Tunnel: Nowhere"].startswith("2 "), lines)

    def test_disabled_child_is_not_required(self):
        config = fixture("ipsec-26.7", "config.xml")
        self.assertIn('<child uuid="dddddddd-0000-4000-8000-000000000002">\n        <enabled>1</enabled>', config)
        config = config.replace('<child uuid="dddddddd-0000-4000-8000-000000000002">\n        <enabled>1</enabled>',
                                '<child uuid="dddddddd-0000-4000-8000-000000000002">\n        <enabled>0</enabled>')
        lines = by_name(vm_ipsec(vm_status(with_children=True), config))
        self.assertTrue(lines["IPsec Tunnel: Loop A"].startswith("0 "), lines["IPsec Tunnel: Loop A"])

    def test_strongswan_not_running(self):
        lines = vm_ipsec("ipsec not active\n")
        self.assertEqual(len(lines), 4, lines)
        self.assertTrue(all(l.startswith("2 ") and l.endswith("not running") for l in lines), lines)

    def test_disabled_connection_and_phase1_are_skipped(self):
        """#39: disabled tunnels are not reported."""
        config = fixture("ipsec-26.7", "config.xml")
        config = config.replace(f'<Connection uuid="{LOOP_B}">\n        <enabled>1</enabled>',
                                f'<Connection uuid="{LOOP_B}">\n        <enabled>0</enabled>')
        config = config.replace("<ikeid>1</ikeid>\n    <iketype>", "<ikeid>1</ikeid>\n    <disabled>1</disabled>\n    <iketype>")
        lines = by_name(vm_ipsec(vm_status(), config))
        self.assertEqual(sorted(lines), ["IPsec Tunnel: Loop A", "IPsec Tunnel: Nowhere"])

    def test_ipsec_disabled(self):
        config = fixture("ipsec-26.7", "config.xml").replace("<enable>1</enable>", "<enable>0</enable>").replace(
            "<enabled>1</enabled>\n      <preferred_oldsa>", "<enabled>0</enabled>\n      <preferred_oldsa>")
        self.assertEqual(vm_ipsec(vm_status(), config), [])


if __name__ == "__main__":
    unittest.main()

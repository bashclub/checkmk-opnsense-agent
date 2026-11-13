import json
import unittest

from harness import FakeOPNsense, config_xml, local_lines

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
        self.assertIn("wg0: 203.0.113.10 - 10.0.0.0/24", lines[0])

    def test_site_to_site_peer_down(self):
        lines = self.run_check(NOW - 3600, NOW - 60)
        site = local_lines(lines, "WireGuard Client: site-a")[0]
        self.assertTrue(site.startswith("2 "), site)
        self.assertIn("last IP:203.0.113.10", site)

    @unittest.expectedFailure  # #52 / #39, PR #85: a roadwarrior without endpoint address is offline most of the time
    def test_roadwarrior_offline_is_ok(self):
        lines = self.run_check(NOW - 30, NOW - 4 * 3600)
        phone = local_lines(lines, "WireGuard Client: phone")[0]
        self.assertTrue(phone.startswith("0 "), phone)


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

    @unittest.expectedFailure  # #34: phase 1 without description crashes (None.strip())
    def test_tunnel_without_description(self):
        lines = self.run_check("")
        self.assertTrue(lines[0].startswith('0 "IPsec Tunnel: 192.0.2.50"'), lines)


if __name__ == "__main__":
    unittest.main()

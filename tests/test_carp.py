"""CARP: the CARP service (#48) and tunnels bound to a CARP VIP on the backup node (#76).

ifconfig output and VIP from the test VM (OPNsense 26.7.9): LAN CARP 10.91.0.190 vhid 91, MASTER and forced to BACKUP.
"""
import json
import unittest

from harness import FakeOPNsense, config_xml, fixture, local_lines

VIP_UUID = "cccc0000-0000-4000-8000-0000000000a1"
VIP = f"""<virtualip version="1.0.1"><vip uuid="{VIP_UUID}"><interface>lan</interface><mode>carp</mode>
<subnet>10.91.0.190</subnet><subnet_bits>24</subnet_bits><vhid>91</vhid><advbase>1</advbase><advskew>{{advskew}}</advskew>
<descr>LAN CARP</descr></vip></virtualip>
<interfaces><lan><enable>1</enable><if>vtnet0</if><descr>LAN</descr></lan></interfaces>"""


def ifconfig(state):
    return fixture("carp-26.7", f"ifconfig-{state}.txt")


def commands(state):
    return {"ifconfig -m -v -f inet:cidr,inet6:cidr": ifconfig(state), "ifconfig -a": ifconfig(state),
            "sysctl net.inet.carp.demotion": "net.inet.carp.demotion: 0\n"}


class TestCarpService(unittest.TestCase):
    def carp(self, state, advskew):
        with FakeOPNsense(config_xml(VIP.format(advskew=advskew)), commands=commands(state)) as checker:
            checker.check_net()
            return checker.checklocal_carpstatus()

    def test_master_as_expected(self):
        self.assertEqual(self.carp("master", 0),
                         ['0 "CARP: LAN@91" master=1 MASTER 10.91.0.190 (vtnet0) demotion:0 advskew:0'])

    def test_backup_with_low_advskew_explains_why(self):
        """#48: WARN on the second node when both have advskew below 50."""
        self.assertEqual(self.carp("backup", 1),
                         ['1 "CARP: LAN@91" master=0 BACKUP 10.91.0.190 (vtnet0) demotion:0 advskew:1, '
                          'expected MASTER (advskew 1 < 50)'])

    def test_backup_as_expected(self):
        self.assertTrue(self.carp("backup", 100)[0].startswith('0 "CARP: LAN@91" master=0 BACKUP'))


class TestCarpStates(unittest.TestCase):
    def test_states_from_ifconfig(self):
        for state in ("master", "backup"):
            with FakeOPNsense(commands=commands(state)) as checker:
                self.assertEqual(checker._carp_states(), {("vtnet0", "91"): state.upper()})

    def test_inactive_vip_references(self):
        with FakeOPNsense(config_xml(VIP.format(advskew=100)), commands=commands("backup")) as checker:
            refs = checker._carp_inactive_vips()
        self.assertEqual(set(refs), {VIP_UUID, "lan_vip91", f"_vip{VIP_UUID}", "10.91.0.190"})
        self.assertEqual(refs[VIP_UUID], "CARP BACKUP on 10.91.0.190 (vhid 91)")
        with FakeOPNsense(config_xml(VIP.format(advskew=0)), commands=commands("master")) as checker:
            self.assertEqual(checker._carp_inactive_vips(), {})


# tunnels from the OpenVPN/IPsec fixtures of the test VM, bound to the VIP
VPN_SOCKETS = {(path, cmd): answer for path, answers in json.loads(fixture("openvpn-26.7", "sockets.json")).items()
               for cmd, answer in answers.items()}
NOWHERE_UUID = "8308e1fc-840f-4c5c-a7a6-1814f2b3262c"


def openvpn(state, bind=True):
    config = fixture("openvpn-26.7", "config.xml")
    if bind:  # client instance "Site Nowhere" depends on the CARP VIP
        config = config.replace("<description>Site Nowhere</description>",
                                f"<description>Site Nowhere</description><carp_depend_on>{VIP_UUID}</carp_depend_on>")
    with FakeOPNsense(config_xml(VIP.format(advskew=0) + config), commands=commands(state), sockets=VPN_SOCKETS) as checker:
        return checker.checklocal_openvpn()


class TestCarpOpenVPN(unittest.TestCase):
    def test_backup_node_bound_client_is_ok(self):
        """#76: on the backup node the tunnel cannot be up, no CRIT."""
        line = local_lines(openvpn("backup"), "OpenVPN Connection: Site Nowhere")[0]
        self.assertTrue(line.startswith('0 "OpenVPN Connection: Site Nowhere" connections_ssl_vpn=0;;|'), line)
        self.assertIn(" CARP BACKUP on 10.91.0.190 (vhid 91), tunnel only runs on the master: WAIT ", line)

    def test_backup_node_client_not_started(self):
        """OPNsense does not start a client instance with carp_depend_on on the backup node: no socket."""
        sockets = {k: v for k, v in VPN_SOCKETS.items() if NOWHERE_UUID not in k[0]}
        config = fixture("openvpn-26.7", "config.xml").replace(
            "<description>Site Nowhere</description>",
            f"<description>Site Nowhere</description><carp_depend_on>{VIP_UUID}</carp_depend_on>")
        with FakeOPNsense(config_xml(VIP.format(advskew=0) + config), commands=commands("backup"), sockets=sockets) as checker:
            line = local_lines(checker.checklocal_openvpn(), "OpenVPN Connection: Site Nowhere")[0]
        self.assertTrue(line.startswith("0 ") and "tunnel only runs on the master: Server down" in line, line)

    def test_master_node_stays_crit(self):
        line = local_lines(openvpn("master"), "OpenVPN Connection: Site Nowhere")[0]
        self.assertTrue(line.startswith("2 "), line)

    def test_unbound_tunnel_stays_crit_on_backup(self):
        line = local_lines(openvpn("backup", bind=False), "OpenVPN Connection: Site Nowhere")[0]
        self.assertTrue(line.startswith("2 "), line)


class TestCarpIPsec(unittest.TestCase):
    def ipsec(self, state):
        config = fixture("ipsec-26.7", "config.xml").replace(  # connection "Nowhere" on the CARP address
            "<local_addrs>10.91.0.185</local_addrs>\n        <remote_addrs>192.0.2.99",
            "<local_addrs>10.91.0.190</local_addrs>\n        <remote_addrs>192.0.2.99")
        self.assertTrue("<local_addrs>10.91.0.190</local_addrs>" in config, "fixture changed")
        status = fixture("ipsec-26.7", "status.json")
        with FakeOPNsense(config_xml(VIP.format(advskew=0) + config),
                          commands=dict(commands(state), **{"/usr/local/opnsense/scripts/ipsec/list_status.py": status})) as checker:
            return {l.split('"')[1]: l for l in checker.checklocal_ipsec()}

    def test_backup_node(self):
        lines = self.ipsec("backup")
        self.assertTrue(lines["IPsec Tunnel: Nowhere"].startswith("0 "), lines["IPsec Tunnel: Nowhere"])
        self.assertIn("tunnel only runs on the master: not connected (CONNECTING)", lines["IPsec Tunnel: Nowhere"])
        self.assertTrue(lines["IPsec Tunnel: Loop A"].startswith("2 "), "not bound to the VIP")

    def test_master_node(self):
        self.assertTrue(self.ipsec("master")["IPsec Tunnel: Nowhere"].startswith("2 "))


if __name__ == "__main__":
    unittest.main()

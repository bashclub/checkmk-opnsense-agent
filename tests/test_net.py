"""Interfaces (statgrab_net): parsed from "ifconfig -m -v" and "netstat -i", filtered by the interfaces in config.xml."""
import unittest

from harness import FakeOPNsense, config_xml

NOW = 1_790_000_000

NETSTAT = """Name    Mtu Network            Address              Ipkts Ierrs Idrop     Ibytes    Opkts Oerrs     Obytes  Coll  Drop
ice0   1500 <Link#1>           f4:90:ea:01:25:ee      100     0     0      10000      200     0      20000     0     0
ice1   1500 <Link#2>           f4:90:ea:01:25:ee      101     0     0      10100      201     0      20100     0     0
lagg0  1500 <Link#17>          f4:90:ea:01:25:ee      201     0     0      20100      401     0      40100     0     0
"""

# from PR #59, FreeBSD indents sub-entries with two tabs
LAGG0 = """lagg0: flags=8943<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST> metric 0 mtu 1500
\toptions=4800028<VLAN_MTU,JUMBO_MTU,NOMAP>
\tether f4:90:ea:01:25:ee
\tinet6 fe80::f690:eaff:fe01:25ee%lagg0/64 scopeid 0x11
\tlaggproto lacp lagghash l2
\tlagg options:
\t\tflags=0<>
\t\tflowid_shift: 16
\tlagg statistics:
\t\tactive ports: 2
\t\tflapping: 0
\tlag id: [(8000,F4-90-EA-01-25-EE,0A28,0000,0000),
\t\t (1000,AA-AA-AA-AA-AA-AA,0023,0000,0000)]
\tlaggport: ice0 flags=1c<ACTIVE,COLLECTING,DISTRIBUTING> state=3d<ACTIVITY,AGGREGATION,SYNC,COLLECTING,DISTRIBUTING>
\t\t[(8000,F4-90-EA-01-25-EE,0A28,8000,0005),
\t\t (1000,AA-AA-AA-AA-AA-AA,0023,8000,0021)]
\tlaggport: ice1 flags=1c<ACTIVE,COLLECTING,DISTRIBUTING> state=3d<ACTIVITY,AGGREGATION,SYNC,COLLECTING,DISTRIBUTING>
\t\t[(8000,F4-90-EA-01-25-EE,0A28,8000,0006),
\t\t (1000,AA-AA-AA-AA-AA-AA,0023,8000,0041)]
\tgroups: lagg
\tmedia: Ethernet autoselect
\tstatus: active
\tsupported media:
\t\tmedia autoselect
\tnd6 options=23<PERFORMNUD,ACCEPT_RTADV,AUTO_LINKLOCAL>
"""


def member(name):
    return f"""{name}: flags=1008943<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\toptions=4e507bb<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,JUMBO_MTU>
\tether f4:90:ea:01:25:ee
\tmedia: Ethernet autoselect (10Gbase-SR <full-duplex>)
\tstatus: active
\tsupported media:
\t\tmedia autoselect
\t\tmedia 10Gbase-SR mediaopt full-duplex
\tnd6 options=29<PERFORMNUD,IFDISABLED>
"""


IFCONFIG = member("ice0") + member("ice1") + LAGG0

# lagg0 is not assigned itself, only the VLANs on top of it would be
CONFIG = config_xml("""
<interfaces><wan><enable>1</enable><if>vlan0.10</if><descr>WAN</descr></wan></interfaces>
<laggs>
  <lagg><laggif>lagg0</laggif><members>ice0,ice1</members><proto>lacp</proto><descr>uplink</descr></lagg>
</laggs>
""")


def run_net(config=CONFIG, ifconfig=IFCONFIG):
    commands = {"/usr/bin/netstat -i -b -d -n -W -f link": NETSTAT, "ifconfig -m -v -f inet:cidr,inet6:cidr": ifconfig}
    with FakeOPNsense(config, commands=commands, now=NOW) as checker:
        lines = checker.check_net()
        return lines, checker._all_interfaces


def values(lines):
    return dict(line.split(" ", 1) for line in lines[1:])


class TestNet(unittest.TestCase):
    def test_lagg_flags_are_not_overwritten_by_lagg_options(self):
        """#59: "flags=0<>" below "lagg options:" replaced the interface flags, the lagg was dropped."""
        _, interfaces = run_net()
        self.assertIn("lagg0", interfaces)
        self.assertEqual(interfaces["lagg0"]["flags"], 0x8943)
        self.assertEqual(interfaces["lagg0"]["up"], "true")

    def test_supported_media_does_not_overwrite_the_speed(self):
        _, interfaces = run_net()
        self.assertEqual(interfaces["ice0"]["speed"], "10000")
        self.assertEqual(interfaces["ice0"]["duplex"], "full-duplex")

    def test_lagg_and_members_are_monitored(self):
        """#60: a lagg and its members are reported even if only VLANs on top are assigned."""
        lines, _ = run_net()
        data = values(lines)
        self.assertEqual(lines[0], "<<<statgrab_net>>>")
        self.assertEqual(data["lagg0.interface_name"], "lagg0")
        self.assertEqual(data["lagg0.up"], "true")
        self.assertEqual(data["lagg0.rx"], "20100")
        self.assertEqual(data["ice0.interface_name"], "lagg0_ice0")
        self.assertEqual(data["ice1.speed"], "10000")

    def test_assigned_lagg_keeps_its_description(self):
        config = CONFIG.replace("</wan>", "</wan><lan><enable>1</enable><if>lagg0</if><descr>LAN</descr></lan>")
        data = values(run_net(config)[0])
        self.assertEqual(data["lagg0.interface_name"], "LAN")

    def test_empty_interfaces_section(self):
        """<interfaces/> (empty) stopped the interface check (None.items())."""
        lines, _ = run_net(config_xml("<interfaces/>"))
        self.assertEqual(lines, ["<<<statgrab_net>>>"])

    def test_without_laggs_only_assigned_interfaces(self):
        config = config_xml("<interfaces><wan><enable>1</enable><if>ice0</if></wan></interfaces>")
        data = values(run_net(config)[0])
        self.assertEqual(data["ice0.interface_name"], "WAN")
        self.assertNotIn("ice1.up", data)
        self.assertNotIn("lagg0.up", data)


if __name__ == "__main__":
    unittest.main()

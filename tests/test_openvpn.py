"""OpenVPN: legacy configuration (<openvpn>) and instances (<OPNsense><OpenVPN><Instances>, since 23.7, only option since 26.1)."""
import unittest

from certs import cert_xml
from harness import FakeOPNsense, config_xml, local_lines

NOW = 1_790_000_000  # fixed time for connection ages

CERTS = cert_xml("srvcert", "vpn.example.org") + cert_xml("clientcert", "site-b.example.org")

LOAD_STATS = "SUCCESS: nclients=1,bytesin=123456,bytesout=654321\r\n"
STATUS_2 = (
    "TITLE,OpenVPN 2.6.14 amd64-portbld-freebsd14.3\r\n"
    "TIME,2026-09-21 12:00:00,1789999200\r\n"
    "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,"
    "Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher\r\n"
    "CLIENT_LIST,alice,198.51.100.7:51234,10.8.0.2,,1000,2000,2026-09-21 11:00:00,1789996400,alice,0,0,AES-256-GCM\r\n"
    "GLOBAL_STATS,Max bcast/mcast queue length,0\r\n"
    "END\r\n"
)
STATE_CONNECTED = (
    "1789990000,CONNECTED,SUCCESS,10.9.0.2,203.0.113.10,1194,192.0.2.1,1194,\r\n"
    "END\r\n"
)

LEGACY_SERVER = """
<openvpn-server>
  <vpnid>1</vpnid>
  <mode>server_tls_user</mode>
  <protocol>UDP</protocol>
  <dev_mode>tun</dev_mode>
  <local_port>1194</local_port>
  <description>{description}</description>
  <tunnel_network>10.8.0.0/24</tunnel_network>
  <topology_subnet>yes</topology_subnet>
  <certref>srvcert</certref>
</openvpn-server>
"""
LEGACY_SERVER_2 = """
<openvpn-server>
  <vpnid>2</vpnid>
  <mode>server_tls_user</mode>
  <protocol>TCP</protocol>
  <dev_mode>tun</dev_mode>
  <local_port>1195</local_port>
  <description>Second</description>
  <tunnel_network>10.18.0.0/24</tunnel_network>
  <topology_subnet>yes</topology_subnet>
  <certref>srvcert</certref>
</openvpn-server>
"""

INSTANCE_SERVER = """
<Instance uuid="11111111-2222-3333-4444-555555555555">
  <vpnid>1</vpnid>
  <enabled>1</enabled>
  <dev_type>tun</dev_type>
  <proto>udp</proto>
  <port>1194</port>
  <topology>subnet</topology>
  <role>server</role>
  <server>10.8.0.0/24</server>
  <cert>srvcert</cert>
  <description>Roadwarrior</description>
</Instance>
"""
INSTANCE_CLIENT = """
<Instance uuid="66666666-7777-8888-9999-000000000000">
  <vpnid>2</vpnid>
  <enabled>1</enabled>
  <dev_type>tun</dev_type>
  <proto>udp</proto>
  <port/>
  <remote>203.0.113.10</remote>
  <topology>subnet</topology>
  <role>client</role>
  <server/>
  <cert>clientcert</cert>
  <description>Site B</description>
</Instance>
"""


def legacy_config(*servers):
    # a real config.xml always has an <OPNsense> section with MVC models
    return config_xml(CERTS + "<openvpn>" + "".join(servers) + "</openvpn><OPNsense><Firewall/></OPNsense>")


def instances_config(*instances):
    return config_xml(CERTS + "<OPNsense><OpenVPN version=\"1.0.1\"><Overwrites/><Instances>"
                      + "".join(instances) + "</Instances></OpenVPN></OPNsense>")


def server_sockets(path):
    return {(path, "load-stats"): LOAD_STATS, (path, "status 2"): STATUS_2}


class TestOpenVPNLegacy(unittest.TestCase):
    def test_two_legacy_servers(self):
        sockets = {**server_sockets("/var/etc/openvpn/server1.sock"), **server_sockets("/var/etc/openvpn/server2.sock")}
        config = legacy_config(LEGACY_SERVER.format(description="Office"), LEGACY_SERVER_2)
        with FakeOPNsense(config, sockets=sockets, now=NOW) as checker:
            lines = checker.checklocal_openvpn()
        servers = local_lines(lines, "OpenVPN Server:")
        self.assertEqual(len(servers), 2, lines)
        self.assertTrue(servers[0].startswith('0 "OpenVPN Server: Office" connections_ssl_vpn=1;;254|'), servers[0])
        self.assertIn("1/254 Connections Port:1194/UDP", servers[0])

    def test_legacy_server_without_description(self):
        """#62/#63: name falls back to OpenVPN_<protocol>_<port>."""
        sockets = {**server_sockets("/var/etc/openvpn/server1.sock"), **server_sockets("/var/etc/openvpn/server2.sock")}
        config = legacy_config(LEGACY_SERVER.format(description=""), LEGACY_SERVER_2)
        with FakeOPNsense(config, sockets=sockets, now=NOW) as checker:
            lines = checker.checklocal_openvpn()
        self.assertTrue(any('"OpenVPN Server: OpenVPN_UDP_1194"' in l for l in lines), lines)

    @unittest.expectedFailure  # #82: since 24922b6 a single legacy server (dict) is replaced by the instances and lost
    def test_single_legacy_server(self):
        config = legacy_config(LEGACY_SERVER.format(description="Office"))
        with FakeOPNsense(config, sockets=server_sockets("/var/etc/openvpn/server1.sock"), now=NOW) as checker:
            lines = checker.checklocal_openvpn()
        self.assertEqual(len(local_lines(lines, "OpenVPN Server: Office")), 1, lines)


class TestOpenVPNInstances(unittest.TestCase):
    SERVER_SOCKET = "/var/etc/openvpn/instance-11111111-2222-3333-4444-555555555555.sock"
    CLIENT_SOCKET = "/var/etc/openvpn/instance-66666666-7777-8888-9999-000000000000.sock"

    @unittest.expectedFailure  # #82 / #67 / #41: instances are not monitored since 24922b6
    def test_server_instance(self):
        with FakeOPNsense(instances_config(INSTANCE_SERVER), sockets=server_sockets(self.SERVER_SOCKET), now=NOW) as checker:
            lines = checker.checklocal_openvpn()
        servers = local_lines(lines, "OpenVPN Server: Roadwarrior")
        self.assertEqual(len(servers), 1, lines)
        self.assertIn("1/254 Connections Port:1194/udp", servers[0])

    @unittest.expectedFailure  # #80 / #71: client instance has no tunnel network (server is empty) and crashes
    def test_client_instance(self):
        sockets = {(self.CLIENT_SOCKET, "load-stats"): LOAD_STATS, (self.CLIENT_SOCKET, "state 1"): STATE_CONNECTED}
        with FakeOPNsense(instances_config(INSTANCE_CLIENT), sockets=sockets, now=NOW) as checker:
            lines = checker.checklocal_openvpn()
        conns = local_lines(lines, "OpenVPN Connection: Site B")
        self.assertEqual(len(conns), 1, lines)
        self.assertTrue(conns[0].startswith("0 "), conns[0])

    @unittest.expectedFailure  # an unreachable management socket raises (bare "raise") instead of reporting "Server down"
    def test_server_instance_socket_down(self):
        with FakeOPNsense(instances_config(INSTANCE_SERVER, INSTANCE_SERVER.replace("1111", "aaaa")), now=NOW) as checker:
            lines = checker.checklocal_openvpn()
        self.assertTrue(any(l.startswith('2 "OpenVPN Server: Roadwarrior"') and "Server down" in l for l in lines), lines)

    def test_disabled_instance_is_skipped(self):
        disabled = INSTANCE_SERVER.replace("<enabled>1</enabled>", "<enabled>0</enabled>")
        with FakeOPNsense(instances_config(disabled, disabled.replace("1111", "bbbb")), now=NOW) as checker:
            lines = checker.checklocal_openvpn()
        self.assertEqual(local_lines(lines, "OpenVPN"), [])


if __name__ == "__main__":
    unittest.main()

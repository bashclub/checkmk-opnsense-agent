"""Local check "Caddy Domain" (plugin os-caddy): upstreams reachable, certificate renewed.

Config and certificate from the test VM: a.internal -> 127.0.0.1:443 (web GUI), b.internal -> 127.0.0.1:9 (down),
certificates of Caddy's internal CA (12 hours, from 2026-11-15 19:43:20 UTC).
"""
import unittest
from unittest import mock

from harness import FakeOPNsense, config_xml, fixture

CERT_START = 1794771800  # 2026-11-15 19:43:20 UTC
CERTDIR = "/var/db/caddy/data/caddy/certificates"
REACHABLE = {("127.0.0.1", "443"): True, ("127.0.0.1", "9"): False}


def run(now, config=None, certs=("a.internal", "b.internal")):
    files = {f"{CERTDIR}/local/{d}/{d}.crt": fixture("caddy-26.7", "a.internal.crt") for d in certs}
    with FakeOPNsense(config_xml(config or fixture("caddy-26.7", "config.xml")), files=files, now=now) as checker:
        with mock.patch.object(checker, "_tcp_reachable", side_effect=lambda h, p, timeout=2: REACHABLE.get((h, str(p)), False)), \
             mock.patch("glob.glob", side_effect=lambda pattern: [f for f in files if f.split("/")[-2] in pattern]):
            return {l.split('"')[1]: l for l in checker.checklocal_caddy()}


class TestCaddy(unittest.TestCase):
    def test_upstream_up_and_down(self):
        lines = run(CERT_START + 3600)
        self.assertRegex(lines["Caddy Domain: a.internal"],
                         r'^0 "Caddy Domain: a\.internal" upstreams_up=1\|upstreams=1\|expiredays=0\.\d upstreams 1/1 reachable, '
                         r'certificate valid until 1[56]\.11\.2026 \d\d:\d\d \(Caddy Local Authority - ECC Intermediate\)$')
        self.assertTrue(lines["Caddy Domain: b.internal"].startswith(
            '2 "Caddy Domain: b.internal" upstreams_up=0|upstreams=1|'), lines["Caddy Domain: b.internal"])
        self.assertIn("upstreams 0/1 reachable, down: 127.0.0.1:9", lines["Caddy Domain: b.internal"])

    def test_renewal_overdue_and_failed(self):
        """internal CA: 12 hours, renewed after 8; less than 2 hours left = overdue, less than 1 hour = failed."""
        self.assertTrue(run(CERT_START + 10.5 * 3600)["Caddy Domain: a.internal"].startswith("1 "))
        self.assertIn("renewal overdue", run(CERT_START + 10.5 * 3600)["Caddy Domain: a.internal"])
        self.assertTrue(run(CERT_START + 11.5 * 3600)["Caddy Domain: a.internal"].startswith("2 "))
        self.assertIn("expired", run(CERT_START + 13 * 3600)["Caddy Domain: a.internal"])

    def test_no_certificate_yet(self):
        line = run(CERT_START + 3600, certs=())["Caddy Domain: a.internal"]
        self.assertTrue(line.startswith("1 ") and "no certificate yet" in line, line)

    def test_custom_certificate_and_disabled(self):
        config = fixture("caddy-26.7", "config.xml").replace(
            "<FromDomain>a.internal</FromDomain>", "<FromDomain>a.internal</FromDomain><CustomCertificate>c1</CustomCertificate>")
        config = config.replace("<enabled>1</enabled>\n        <FromDomain>b.internal", "<enabled>0</enabled>\n        <FromDomain>b.internal")
        lines = run(CERT_START + 3600, config)
        self.assertEqual(list(lines), ["Caddy Domain: a.internal"])
        self.assertIn("custom certificate (service Certificate)", lines["Caddy Domain: a.internal"])

    def test_caddy_disabled(self):
        config = fixture("caddy-26.7", "config.xml").replace("<enabled>1</enabled>\n      <HttpPort>", "<enabled>0</enabled>\n      <HttpPort>")
        self.assertEqual(run(CERT_START, config), {})


if __name__ == "__main__":
    unittest.main()

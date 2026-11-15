"""Local check "Certificate"/"CA": expiry of all certificates and CAs in System > Trust (#66)."""
import datetime
import unittest

from certs import make_cert_b64
from harness import FakeOPNsense, config_xml


def entry(kind, refid, descr, days, cn=None, prv=True):
    now = None
    if days < 0:  # expired: issued earlier, valid for 5 days
        now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=5 - days)
        days = 5
    key = "<prv>a2V5</prv>" if prv else ""
    return (f"<{kind}><refid>{refid}</refid><descr>{descr}</descr>"
            f"<crt>{make_cert_b64(cn or descr, days, now)}</crt>{key}</{kind}>")


def run(body, skipcert=()):
    with FakeOPNsense(config_xml(body)) as checker:
        checker.skipcert = list(skipcert)
        return {line.split('"')[1]: line for line in checker.checklocal_certificates()}


class TestCertificates(unittest.TestCase):
    def test_states_by_levels(self):
        lines = run(entry("ca", "ca1", "Internal CA", 3650) + entry("cert", "c1", "Web GUI", 400, "fw.example.org")
                    + entry("cert", "c2", "VPN alice", 20) + entry("cert", "c3", "VPN bob", 5)
                    + entry("cert", "c4", "VPN old", -3))
        self.assertEqual(sorted(lines), ["CA: Internal CA", "Certificate: VPN alice", "Certificate: VPN bob",
                                         "Certificate: VPN old", "Certificate: Web GUI"])
        self.assertRegex(lines["Certificate: Web GUI"],
                         r'^P "Certificate: Web GUI" expiredays=(399|400);30:;14: CN fw\.example\.org, issuer fw\.example\.org, '
                         r'expires on \d\d\.\d\d\.\d{4} \((399|400) days\)$')
        self.assertRegex(lines["Certificate: VPN alice"], r"expiredays=(19|20);30:;14: ")
        self.assertRegex(lines["Certificate: VPN old"], r"expiredays=-[34];30:;14: .*, expired on ")

    def test_acme_certificates_are_skipped(self):
        acme = ("<OPNsense><AcmeClient><certificates><certificate><enabled>1</enabled><certRefId>acme1</certRefId>"
                "</certificate></certificates></AcmeClient></OPNsense>")
        lines = run(entry("cert", "acme1", "www.example.org", 60) + entry("cert", "c1", "Web GUI", 400) + acme)
        self.assertEqual(list(lines), ["Certificate: Web GUI"])

    def test_skipcert_by_description_cn_or_refid(self):
        body = (entry("cert", "c1", "VPN alice", 20, "alice") + entry("cert", "c2", "VPN bob", 20, "bob")
                + entry("cert", "c3", "VPN carol", 20) + entry("cert", "c4", "Web GUI", 400))
        self.assertEqual(list(run(body, skipcert=["vpn alice", "bob", "c3"])), ["Certificate: Web GUI"])

    def test_same_description_twice(self):
        lines = run(entry("cert", "c1", "Web GUI", 400) + entry("cert", "c2", "Web GUI", 30))
        self.assertEqual(sorted(lines), ["Certificate: Web GUI", "Certificate: Web GUI (c2)"])

    def test_signing_request_and_broken_entries(self):
        body = ("<cert><refid>csr</refid><descr>pending</descr><csr>xyz</csr></cert>"
                "<cert><refid>bad</refid><descr>broken</descr><crt>bm8gY2VydA==</crt></cert>"
                + entry("cert", "c1", "Web GUI", 400))
        self.assertEqual(list(run(body)), ["Certificate: Web GUI"])

    def test_imported_cas_without_key_are_skipped(self):
        """feedback: the ACME client imports intermediates (R3, R10, YR1, staging) as CAs without private key."""
        lines = run(entry("ca", "ca1", "OVPN_CA", 3650) + entry("ca", "r10", "R10", 117, prv=False)
                    + entry("ca", "r3", "R3", -3, prv=False))
        self.assertEqual(list(lines), ["CA: OVPN_CA"])

    def test_acme_client_suffix_is_skipped(self):
        """an older ACME certificate no longer referenced by the ACME client"""
        lines = run(entry("cert", "old", "*.example.org (ACME Client)", -3) + entry("cert", "c1", "Web GUI", 400))
        self.assertEqual(list(lines), ["Certificate: Web GUI"])

    def test_long_expired_is_not_reported(self):
        """feedback: user certificates expired years ago are no longer in use."""
        lines = run(entry("cert", "c1", "christian", -912) + entry("cert", "c2", "recent", -3))
        self.assertEqual(list(lines), ["Certificate: recent"])

    def test_quotes_are_removed(self):
        """feedback: (Let's Encrypt) in the name made Checkmk report "Invalid data"."""
        lines = run(entry("ca", "s1", "(STAGING) Apricot R3 (Let's Encrypt)", 100, cn='Quote "CA"'))
        self.assertEqual(list(lines), ["CA: (STAGING) Apricot R3 (Lets Encrypt)"])
        self.assertNotIn("'", lines["CA: (STAGING) Apricot R3 (Lets Encrypt)"])
        self.assertIn("CN Quote CA, issuer Quote CA", lines["CA: (STAGING) Apricot R3 (Lets Encrypt)"])

    def test_no_certificates(self):
        self.assertEqual(run(""), {})


if __name__ == "__main__":
    unittest.main()

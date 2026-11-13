"""Firmware check: version from /usr/local/opnsense/version/core, updates from /tmp/pkg_upgrade.json."""
import json
import unittest

from harness import FakeOPNsense

NOW = 1_795_000_000  # 2026-11-18, after the release dates in CHANGELOG

CORE = {"product_name": "OPNsense", "product_version": "26.7.9", "product_series": "26.7", "product_id": "opnsense"}
CHANGELOG = [
    {"series": "26.7", "version": "26.7.9", "date": "November 05, 2026"},
    {"series": "26.7", "version": "26.7.8", "date": "October 22, 2026"},
    {"series": "26.1", "version": "26.1.12", "date": "July 15, 2026"},
]


def pkg_upgrade(upgrade_packages=(), major=""):
    return {
        "api_version": "2", "connection": "ok", "repository": "ok", "product_version": "26.7.9",
        "upgrade_major_version": major, "upgrade_major_message": "", "new_packages": [],
        "upgrade_packages": list(upgrade_packages),
    }


def run_firmware(files):
    base = {"/usr/local/opnsense/version/core": json.dumps(CORE),
            "/usr/local/opnsense/changelog/index.json": json.dumps(CHANGELOG),
            "/conf/config.xml": "<opnsense/>"}
    base.update(files)
    for path, content in list(base.items()):
        if content is None:
            del base[path]
    with FakeOPNsense(files=base, commands={"hostname": "fw.example.org\n"}, now=NOW) as checker:
        checker._getosinfo()
        return checker.checklocal_firmware()[0]


class TestFirmware(unittest.TestCase):
    def test_no_updates(self):
        line = run_firmware({"/tmp/pkg_upgrade.json": json.dumps(pkg_upgrade())})
        self.assertTrue(line.startswith("0 Firmware update_available=0"), line)
        self.assertIn("Version 26.7.9", line)

    def test_no_pkg_upgrade_json(self):
        line = run_firmware({})
        self.assertTrue(line.startswith("0 Firmware update_available=0"), line)

    def test_core_update(self):
        upgrade = pkg_upgrade([{"name": "opnsense", "current_version": "26.7.9", "new_version": "26.7.10"}])
        line = run_firmware({"/tmp/pkg_upgrade.json": json.dumps(upgrade)})
        self.assertTrue(line.startswith("1 Firmware update_available=1"), line)
        self.assertIn("26.7.10 available", line)

    def test_business_core_update(self):
        upgrade = pkg_upgrade([{"name": "opnsense-business", "current_version": "26.4", "new_version": "26.4.1"}])
        line = run_firmware({"/tmp/pkg_upgrade.json": json.dumps(upgrade)})
        self.assertTrue(line.startswith("1 Firmware update_available=1"), line)

    def test_major_upgrade(self):
        """#46: a major upgrade (e.g. 26.7 -> 27.1) is offered without packages in upgrade_packages."""
        line = run_firmware({"/tmp/pkg_upgrade.json": json.dumps(pkg_upgrade(major="27.1"))})
        self.assertTrue(line.startswith("1 Firmware update_available=1"), line)
        self.assertIn("27.1 available", line)

    @unittest.expectedFailure  # #84: updates of plugins/packages without a new core version are not reported
    def test_package_only_update(self):
        upgrade = pkg_upgrade([{"name": "openvpn", "current_version": "2.6.14", "new_version": "2.6.15"}])
        line = run_firmware({"/tmp/pkg_upgrade.json": json.dumps(upgrade)})
        self.assertTrue(line.startswith("1 Firmware update_available=1"), line)
        self.assertIn("openvpn", line)

    @unittest.expectedFailure  # #74: missing changelog (air-gapped, own mirror) makes _getosinfo crash
    def test_missing_changelog(self):
        line = run_firmware({"/usr/local/opnsense/changelog/index.json": None,
                             "/tmp/pkg_upgrade.json": json.dumps(pkg_upgrade())})
        self.assertIn("Version 26.7.9", line)

    def test_broken_pkg_upgrade_json(self):
        """#87: broken JSON from the OPNsense must not stop the agent."""
        line = run_firmware({"/tmp/pkg_upgrade.json": '{"api_version":"2","upgrade_packages":[{"name":'})
        self.assertIn("Version 26.7.9", line)


if __name__ == "__main__":
    unittest.main()

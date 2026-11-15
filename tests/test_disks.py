"""Local check "Disks": SMART state and wearout like "PVE Disks" of cmk-push-agent.

smartctl output of three bare-metal OPNsense 26.7.9 firewalls (serial numbers replaced): Samsung SSD 840 EVO (SATA,
wear attribute 177), VICKTER SSD (SATA, attribute 173), Samsung PM9A1 (NVMe, also listed as /dev/nda0 with
"INQUIRY failed", last self-test "Aborted: Self-test command").
"""
import copy
import json
import os
import tempfile
import unittest
from unittest import mock

from harness import FakeOPNsense, fixture

NOW = 1_795_000_000
DAY = 86400


def disk(name, device):
    return json.loads(fixture("smart-26.7", f"{name}-{device}.json"))


class Disks:
    """runs the check against fixtures; smartctl answers per device, state in a temporary file"""

    def __init__(self, name, changes=None, dmesg=""):
        self.scan = json.loads(fixture("smart-26.7", f"{name}-scan.json"))
        self.devices = {}
        for dev in self.scan["devices"]:
            device = dev["name"].split("/")[-1]
            self.devices[dev["name"]] = disk(name, device)
        for device, change in (changes or {}).items():
            change(self.devices[device])
        self.zpool = fixture("smart-26.7", f"{name}-zpool.txt")
        self.dmesg = dmesg
        self.tmp = tempfile.TemporaryDirectory()

    def smartctl(self, *args):
        if "--scan-open" in args:
            return copy.deepcopy(self.scan)
        return copy.deepcopy(self.devices[args[-1]])

    def run(self, now=NOW, which="/usr/local/sbin/smartctl"):
        with FakeOPNsense(commands={"zpool status -P": self.zpool, "dmesg": self.dmesg}, now=now) as checker:
            checker.DISKS_STATE = os.path.join(self.tmp.name, "disks.json")
            with mock.patch.object(checker, "_smartctl_json", side_effect=self.smartctl), \
                 mock.patch("shutil.which", return_value=which):
                return {l.split('"')[1]: l for l in checker._disks_lines(now)} if which else checker.checklocal_disks()


class TestRealDisks(unittest.TestCase):
    def test_samsung_840_evo(self):
        lines = Disks("samsung-840-evo").run()
        self.assertEqual(lines["Disks"], '0 "Disks" disks=1;;;0 1 disk(s) (1 SSD/NVMe, 0 HDD/other)')
        self.assertEqual(lines["Disk TESTSERIAL840EVO SMART"],
                         '0 "Disk TESTSERIAL840EVO SMART" temp=27;;;|power_on_hours=39779;;;0 SMART PASSED, '
                         '/dev/ada0 Samsung SSD 840 EVO 250GB (ssd, 250 GB)')
        self.assertEqual(lines["Disk TESTSERIAL840EVO Wearout"],
                         '0 "Disk TESTSERIAL840EVO Wearout" life_remaining=82;20;10;0;100 remaining life 82% '
                         '(from Wear_Leveling_Count), /dev/ada0 Samsung SSD 840 EVO 250GB (ssd, 250 GB)')

    def test_vickter_with_attribute_173_and_198(self):
        lines = Disks("vickter-ssd").run()
        self.assertIn("uncorr=0;;;0|temp=33", lines["Disk TESTSERIALVICKTER SMART"])
        self.assertIn("remaining life 100% (from Unknown_Attribute)", lines["Disk TESTSERIALVICKTER Wearout"])

    def test_nvme_listed_twice_and_aborted_self_test(self):
        """/dev/nda0 fails to open and is skipped; an aborted self-test (code 1) is no failure (pve-disks: CRIT)."""
        lines = Disks("samsung-pm9a1-nvme").run()
        self.assertEqual(sorted(lines), ["Disk TESTSERIALPM9A1 SMART", "Disk TESTSERIALPM9A1 Wearout", "Disks"])
        self.assertTrue(lines["Disk TESTSERIALPM9A1 SMART"].startswith(
            '0 "Disk TESTSERIALPM9A1 SMART" spare=100;20;10;0;100|temp=79;;;|power_on_hours=20332;;;0 SMART PASSED'))
        self.assertIn("life_remaining=88;20;10;0;100|data_written=18721473024000B;;;0 remaining life 88% "
                      "(from NVMe Percentage Used), written 18.7 TB", lines["Disk TESTSERIALPM9A1 Wearout"])


def set_attr(attr_id, **values):
    def change(data):
        for attr in data["ata_smart_attributes"]["table"]:
            if attr["id"] == attr_id:
                attr.update(values)
    return change


class TestFindings(unittest.TestCase):
    def test_smart_failed(self):
        lines = Disks("samsung-840-evo", {"/dev/ada0": lambda d: d["smart_status"].update(passed=False)}).run()
        line = lines["Disk TESTSERIAL840EVO SMART"]
        self.assertTrue(line.startswith("2 ") and "SMART self-assessment FAILED" in line, line)
        self.assertIn("replace the disk - ZFS pool zroot: replace the disk with zpool replace zroot", line)

    def test_attribute_below_threshold_and_temperature(self):
        lines = Disks("samsung-840-evo", {"/dev/ada0": set_attr(5, when_failed="now")}).run()
        self.assertIn("attribute(s) below the vendor threshold: Reallocated_Sector_Ct", lines["Disk TESTSERIAL840EVO SMART"])
        lines = Disks("vickter-ssd", {"/dev/ada0": set_attr(194, when_failed="now")}).run()
        line = lines["Disk TESTSERIALVICKTER SMART"]
        self.assertTrue(line.startswith("2 ") and "check cooling/airflow" in line and "replace the disk" not in line, line)

    def test_failed_nvme_self_test(self):
        def fail(data):
            data["nvme_self_test_log"]["table"][0]["self_test_result"] = {"value": 7, "string": "Failed: segments"}
        line = Disks("samsung-pm9a1-nvme", {"/dev/nvme0": fail}).run()["Disk TESTSERIALPM9A1 SMART"]
        self.assertTrue(line.startswith("2 ") and "last self-test failed: Failed: segments" in line, line)
        self.assertIn("zpool replace zroot", line, "nvme0 is nda0 in the pool")

    def test_nvme_spare_close_to_threshold(self):
        def spare(data):
            data["nvme_smart_health_information_log"]["available_spare"] = 15
        line = Disks("samsung-pm9a1-nvme", {"/dev/nvme0": spare}).run()["Disk TESTSERIALPM9A1 SMART"]
        self.assertTrue(line.startswith("1 ") and "spare blocks 15% only just above the threshold 10%" in line, line)

    def test_rising_counter_warns_for_a_week(self):
        run = Disks("vickter-ssd")
        run.run(NOW)  # baseline 0
        run.devices["/dev/ada0"] = disk("vickter-ssd", "ada0")
        set_attr(198, raw={"value": 3, "string": "3"})(run.devices["/dev/ada0"])
        line = run.run(NOW + DAY)["Disk TESTSERIALVICKTER SMART"]
        self.assertTrue(line.startswith("1 ") and "uncorrectable sectors (198) rose to 3 (before 0," in line, line)
        line = run.run(NOW + 9 * DAY)["Disk TESTSERIALVICKTER SMART"]
        self.assertTrue(line.startswith("0 ") and "3 uncorrectable sectors (198) (stable)" in line, line)

    def test_wearout_levels_and_forecast(self):
        run = Disks("samsung-840-evo")
        for life, state in ((15, "1 "), (8, "2 ")):
            set_attr(177, value=life)(run.devices["/dev/ada0"])
            self.assertTrue(run.run()["Disk TESTSERIAL840EVO Wearout"].startswith(state), life)
        run = Disks("samsung-840-evo")
        set_attr(177, value=60)(run.devices["/dev/ada0"])
        run.run(NOW)
        set_attr(177, value=40)(run.devices["/dev/ada0"])  # 20 points in 40 days: 0% in 80 days
        line = run.run(NOW + 40 * DAY)["Disk TESTSERIAL840EVO Wearout"]
        self.assertTrue(line.startswith("1 ") and "forecast 0% in about 80 days" in line, line)
        self.assertIn("order a spare disk", line)


class TestWithoutDisks(unittest.TestCase):
    def test_without_smartctl(self):
        self.assertEqual(Disks("samsung-840-evo").run(which=None), [])

    def test_virtual_machine(self):
        run = Disks("samsung-840-evo", dmesg="Hypervisor: Origin = \"KVMKVMKVM\"\n")
        run.scan["devices"] = []
        self.assertEqual(run.run(), {})

    def test_no_disks_on_hardware(self):
        run = Disks("samsung-840-evo")
        run.scan["devices"] = []
        self.assertTrue(run.run()["Disks"].startswith('3 "Disks" disks=0'))

    def test_cached_for_30_minutes(self):
        run = Disks("samsung-840-evo")
        calls = []
        with FakeOPNsense(commands={"zpool status -P": run.zpool}, now=NOW) as checker:
            checker.DISKS_STATE = os.path.join(run.tmp.name, "disks.json")
            with mock.patch.object(checker, "_smartctl_json", side_effect=lambda *a: calls.append(a) or run.smartctl(*a)), \
                 mock.patch("shutil.which", return_value="/usr/local/sbin/smartctl"):
                first = checker.checklocal_disks()
                count = len(calls)
                self.assertEqual(checker.checklocal_disks(), first)
                self.assertEqual(len(calls), count, "second call within 30 minutes reads the cache")


if __name__ == "__main__":
    unittest.main()

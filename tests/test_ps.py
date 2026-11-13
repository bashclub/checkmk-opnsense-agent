import unittest

from harness import FakeOPNsense

PS_OUTPUT = """\
STAT USER     VSZ   RSS %CPU COMMAND
Ss   root   13636  2764  0.0 /sbin/init
S    root   21480 10664  0.0 /usr/local/sbin/lighttpd -f /var/etc/lighty-webConfigurator.conf
S<   root  412300 98112  1.5 eastpect: Eastpect Instance 0 (eastpect)
I<   root   18400  4096  0.0 ipdrstreamer /usr/local/zenarmor//output//active//temp/
SN   nobody 15000  3000  0.0 /usr/local/bin/some-niced-daemon
"""


class TestPs(unittest.TestCase):
    def run_check(self):
        with FakeOPNsense(commands={"ps ax -o state,user,vsz,rss,pcpu,command": PS_OUTPUT}) as checker:
            return checker.check_ps()

    def test_section_header_and_normal_processes(self):
        lines = self.run_check()
        self.assertEqual(lines[0], "<<<ps>>>")
        self.assertIn("(root,13636,2764,0.0) /sbin/init", lines)
        self.assertIn("(nobody,15000,3000,0.0) /usr/local/bin/some-niced-daemon", lines)
        self.assertFalse(any("COMMAND" in l for l in lines), "header line of ps must not be reported")

    @unittest.expectedFailure  # #86: state "S<" / "I<" does not match \w+
    def test_processes_with_priority_flags(self):
        lines = self.run_check()
        self.assertIn("(root,412300,98112,1.5) eastpect: Eastpect Instance 0 (eastpect)", lines)
        self.assertIn("(root,18400,4096,0.0) ipdrstreamer /usr/local/zenarmor//output//active//temp/", lines)


if __name__ == "__main__":
    unittest.main()

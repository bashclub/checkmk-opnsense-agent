"""Test harness: runs the checks of the agent without an OPNsense.

The agent reads its data from /conf/config.xml (`_config_reader`), from programs (`_run_prog`), from a few files with
absolute paths (`open`, `os.path.exists`) and from the OpenVPN management sockets (`_read_from_openvpnsocket`).
`FakeOPNsense` replaces exactly these four with test data; everything else is the real code of the agent.
"""
import importlib.util
import io
import os
import sys
import time
import types
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
AGENT_PATH = REPO / "opnsense_checkmk_agent.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# paths the agent reads on an OPNsense; in the tests they come only from the test data, never from the test machine
SYSTEM_PREFIXES = ("/conf/", "/usr/local/opnsense/", "/usr/local/etc/", "/tmp/pkg_upgrade.json", "/var/", "/etc/os-release")

_agent = None


def _stub_platform_modules():
    """unbound and pyOpenSSL exist on the OPNsense, but are only needed by tasks that the tests do not run."""
    try:
        import unbound  # noqa: F401
    except ImportError:
        unbound = types.ModuleType("unbound")
        unbound.RR_TYPE_TXT = 16
        sys.modules["unbound"] = unbound
    try:
        from OpenSSL import SSL, crypto  # noqa: F401
    except ImportError:
        openssl = types.ModuleType("OpenSSL")
        openssl.SSL = types.ModuleType("OpenSSL.SSL")
        openssl.crypto = types.ModuleType("OpenSSL.crypto")
        sys.modules["OpenSSL"] = openssl
        sys.modules["OpenSSL.SSL"] = openssl.SSL
        sys.modules["OpenSSL.crypto"] = openssl.crypto


def load_agent():
    global _agent
    if _agent is None:
        _stub_platform_modules()
        spec = importlib.util.spec_from_file_location("opnsense_checkmk_agent", AGENT_PATH)
        module = importlib.util.module_from_spec(spec)
        with mock.patch("os.mkdir"):  # the agent creates its directories under /usr/local on import
            spec.loader.exec_module(module)
        _agent = module
    return _agent


def fixture(*parts):
    return (FIXTURES.joinpath(*parts)).read_text(encoding="utf-8")


def config_xml(body):
    """Wrap a fragment in <opnsense>…</opnsense> so that tests only write the part they need."""
    return f"<?xml version=\"1.0\"?>\n<opnsense>\n{body}\n</opnsense>\n"


class FakeOPNsense:
    """Context manager that yields a checker reading the given test data.

    config:   content of /conf/config.xml (str)
    commands: {"command line": "output"}; lists are joined with spaces; unknown commands return "" like a failing
              program in `_run_prog`, they are recorded in `unknown_commands`
    files:    {"/absolute/path": "content"}; other paths below SYSTEM_PREFIXES do not exist
    sockets:  {("/path/to.sock", "command"): "answer"}; a missing socket raises ConnectionRefusedError
    now:      fixed time.time() for the checks
    """

    def __init__(self, config="<opnsense/>", commands=None, files=None, sockets=None, now=None):
        self.agent = load_agent()
        self.config = config
        self.commands = dict(commands or {})
        self.files = dict(files or {})
        self.sockets = dict(sockets or {})
        self.now = now
        self.unknown_commands = []
        self._patches = []

    # --- replacements -------------------------------------------------------------------------------------------
    def _config_reader(self, config=""):
        root = ElementTree.fromstring(self.config.encode("utf-8"))
        return self.agent.etree_to_dict(root).get("opnsense", {}) or {}

    def _run_prog(self, cmdline="", *args, **kwargs):
        key = cmdline if isinstance(cmdline, str) else " ".join(cmdline)
        if key in self.commands:
            return self.commands[key]
        self.unknown_commands.append(key)
        return ""

    def _read_from_openvpnsocket(self, vpnsocket, cmd):
        try:
            return self.sockets[(vpnsocket, cmd)]
        except KeyError:
            raise ConnectionRefusedError(f"no test data for {vpnsocket} {cmd}") from None

    def _is_system_path(self, path):
        return isinstance(path, str) and path.startswith(SYSTEM_PREFIXES)

    def _open(self, path, mode="r", *args, **kwargs):
        if path in self.files:
            if "w" in mode or "a" in mode:
                raise PermissionError(f"tests do not write {path}")
            data = self.files[path]
            return io.BytesIO(data.encode("utf-8")) if "b" in mode else io.StringIO(data)
        if self._is_system_path(path):
            raise FileNotFoundError(path)
        return open(path, mode, *args, **kwargs)

    def _exists(self, path, _real=os.path.exists):
        if path in self.files:
            return True
        if self._is_system_path(str(path)):
            return False
        return _real(path)

    def _stat(self, path, *args, _real=os.stat, **kwargs):
        if path in self.files:
            mtime = self.now or time.time()
            return os.stat_result((0o100644, 0, 0, 1, 0, 0, len(self.files[path]), mtime, mtime, mtime))
        if self._is_system_path(str(path)):
            raise FileNotFoundError(path)
        return _real(path, *args, **kwargs)

    # --- context manager ----------------------------------------------------------------------------------------
    def __enter__(self):
        agent = self.agent
        fake = self

        class Checker(agent.checkmk_checker):
            _config_reader = lambda self, config="": fake._config_reader(config)  # noqa: E731
            _run_prog = lambda self, cmdline="", *a, **kw: fake._run_prog(cmdline, *a, **kw)  # noqa: E731
            _read_from_openvpnsocket = staticmethod(fake._read_from_openvpnsocket)

        checker = Checker()
        # class attributes of checkmk_checker are shared state: every test starts empty
        checker._datastore = agent.object_dict()
        checker._check_cache = {}
        checker._certificate_timestamp = 0
        checker._certificate_store = {}
        checker._ipaccess_log = {}

        self._patches = [
            mock.patch.object(agent, "open", self._open, create=True),
            mock.patch.object(agent.os.path, "exists", self._exists),
            mock.patch.object(agent.os, "stat", self._stat),
        ]
        if self.now is not None:
            self._patches.append(mock.patch.object(agent.time, "time", lambda: self.now))
        for p in self._patches:
            p.start()
        return checker

    def __exit__(self, *exc):
        for p in reversed(self._patches):
            p.stop()
        return False


def local_lines(lines, prefix):
    """Local check lines whose service name starts with prefix, e.g. 'OpenVPN Server:'."""
    return [l for l in lines if l.split(" ", 1)[-1].lstrip('"').startswith(prefix)]

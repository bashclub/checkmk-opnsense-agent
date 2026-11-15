# checkmk-opnsense-agent

Like checkmk-opnsense-agent?

<a href="https://ko-fi.com/A0A1J73JR"><img src="docs/kofi-button-en.png" alt="Support the development" height="41"></a>

> **Development has moved to https://code.bashclub.org/bashclub/checkmk-opnsense-agent**
>
> The repository on GitHub (https://github.com/bashclub/checkmk-opnsense-agent) is only a read-only mirror.
> Please open issues and pull requests at https://code.bashclub.org/bashclub/checkmk-opnsense-agent/issues,
> issues and pull requests on GitHub are no longer handled.

Checkmk agent for OPNsense, written in Python and running with the Python interpreter of the OPNsense.

## How to install

SSH into your OPNsense:
```
fetch -o /usr/local/etc/rc.syshook.d/start/99-checkmk_agent https://code.bashclub.org/bashclub/checkmk-opnsense-agent/raw/branch/main/opnsense_checkmk_agent.py
chmod +x /usr/local/etc/rc.syshook.d/start/99-checkmk_agent
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent
```

Ensure you create a packet filter rule to allow connections from your checkmk server to the firewall on port 6556.

## Updates: release and testing

There are two versions: the release (branch `main`) and the testing version (branch `testing`), where fixes go first.
```
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --update           # release
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --update testing   # testing version
```
The local check `Checkmk Agent Update` looks once a day for a new version on code.bashclub.org and goes WARN when an
update is available (release users are only told about releases, testing users also about newer testing versions).
Without internet access it stays OK. To switch it off, add `agentupdate` to `skipcheck` in `/usr/local/etc/checkmk.conf`.

### Automatic update (1.2.20+)

```
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --install-cron                                  # daily 03:00, release
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --install-cron "30 4 * * 1" --cron-branch testing  # own schedule
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --uninstall-cron
```
The job shows up in System > Settings > Cron and runs `--update --yes`: no questions, only a newer version (never a
downgrade), the new file must compile, the agent is restarted; the result is in the system log (`update: ...`).

## Documentation

The handbook (German, English to follow): https://docs.bashclub.org/s/checkmk-opnsense-agent – installation,
connecting to Checkmk (`onlyfrom`, encryption), all options and services, troubleshooting. The source is
[docs/handbuch](docs/handbuch/_collection.md). Changes: [CHANGELOG.md](CHANGELOG.md), planned features:
[ROADMAP.md](ROADMAP.md).

## Tests

The tests run without an OPNsense: `tests/harness.py` feeds the checks with test data for `config.xml`, program
output, files and the OpenVPN management sockets. Needs Python 3 with `cryptography` and `requests`:
```
python3 -m unittest discover -s tests -v
```
Tests marked `expectedFailure` describe known bugs (issue number in the comment). After a fix, remove the marker.

## Contributing

Bug reports, feature requests and pull requests go to https://code.bashclub.org/bashclub/checkmk-opnsense-agent.
To get an account there, log in with your GitHub account or register on the site.

# Author

Original developer: Nils Stöver. Maintained in the repository by Christian Zengel (Chriz) and Thorsten Spille.

### Thorsten Spille
[<img src="https://storage.ko-fi.com/cdn/brandasset/kofi_s_tag_dark.png" rel="Support me on Ko-Fi">](https://ko-fi.com/thorakel)

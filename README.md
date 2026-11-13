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

## Contributing

Bug reports, feature requests and pull requests go to https://code.bashclub.org/bashclub/checkmk-opnsense-agent.
To get an account there, log in with your GitHub account or register on the site.

# Author

### Thorsten Spille
[<img src="https://storage.ko-fi.com/cdn/brandasset/kofi_s_tag_dark.png" rel="Support me on Ko-Fi">](https://ko-fi.com/thorakel)

# check-opnsense

## How to install

SSH into your OPNsense:
```
fetch -o /usr/local/etc/rc.syshook.d/start/99-checkmk_agent https://github.com/bashclub/check-opnsense/raw/main/opnsense_checkmk_agent.py
chmod +x /usr/local/etc/rc.syshook.d/start/99-checkmk_agent
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent
```

Ensure you create a packet filter rule to allow connections from your checkmk server to the firewall on port 6556.

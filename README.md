# check-opnsense

## How to install

```
fetch -o /usr/local/etc/rc.syshook.d/start/99-checkmk_agent https://github.com/bashclub/check-opnsense/raw/main/opnsense_checkmk_agent.py
chmod +x /usr/local/etc/rc.syshook.d/start/99-checkmk_agent
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent start
```

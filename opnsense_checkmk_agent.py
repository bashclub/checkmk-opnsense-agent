#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: set fileencoding=utf-8:noet

##  Copyright 2022 Bashclub
##  BSD-2-Clause
##
##  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
##
##  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
##
##  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
##
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
## THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
## BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
## GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
## LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## OPNsense CheckMK Agent
## to install
## copy to /usr/local/etc/rc.syshook.d/start/99-checkmk_agent and chmod +x
##

__VERSION__ = "0.6"

import sys
import os
import shlex
import re
import time
import json
import socket
import signal
import struct
import subprocess
import pwd
import threading
import ipaddress
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from xml.etree import cElementTree as ELementTree
from collections import Counter,defaultdict
from pprint import pprint
from socketserver import TCPServer,StreamRequestHandler

class object_dict(defaultdict):
    def __getattr__(self,name):
        return self[name] if name in self else ""

def etree_to_dict(t):
    d = {t.tag: {} if t.attrib else None}
    children = list(t)
    if children:
        dd = object_dict(list)
        for dc in map(etree_to_dict, children):
            for k, v in dc.items():
                dd[k].append(v)
        d = {t.tag: {k:v[0] if len(v) == 1 else v for k, v in dd.items()}}
    if t.attrib:
        d[t.tag].update(('@' + k, v) for k, v in t.attrib.items())
    if t.text:
        text = t.text.strip()
        if children or t.attrib:
            if text:
              d[t.tag]['#text'] = text
        else:
            d[t.tag] = text
    return d

class checkmk_handler(StreamRequestHandler):
    def handle(self):
        with self.server._mutex:
            try:
                _strmsg = self.server.do_checks()
            except Exception as e:
                _strmsg = str(e)
            with self.wfile as _f:
                _f.write(_strmsg.encode("utf-8"))

class checkmk_checker(object):
    _certificate_timestamp = 0
    def do_checks(self):
        self._getosinfo()
        _lines = ["<<<check_mk>>>"]
        _lines.append("AgentOS: {os}".format(**self._info))
        _lines.append(f"Version: {__VERSION__}")
        _lines.append("Hostname: {hostname}".format(**self._info))
        _lines += self.check_cpu()
        _lines += self.check_uptime()
        _lines += self.check_df()
        _lines += self.check_ps()
        _lines += self.check_zfs()
        _lines += self.check_mounts()
        _lines += self.check_netctr()
        _lines += self.check_net()
        _lines += self.check_tcp()
        _lines += self.check_ntp()
        _lines += self.check_dhcp()
        _lines.append("<<<local:sep(0)>>>")
        _lines += self.check_firmware()
        _lines += self.check_openvpn()
        _lines.append("")
        return "\n".join(_lines)

    def _getosinfo(self):
        _info = json.load(open("/usr/local/opnsense/version/core","r"))
        _changelog = json.load(open("/usr/local/opnsense/changelog/index.json","r"))
        self._info = {
            "os"                : _info.get("product_name"),
            "os_version"        : _info.get("product_version"),
            "product_series"    : _info.get("product_series"),
            "latest_version"    : list(filter(lambda x: x.get("series") == _info.get("product_series"),_changelog))[-1].get("version"),
            "hostname"          : self._run_prog("hostname").strip(" \n")
        }

    @staticmethod
    def ip2int(ipaddr):
        return struct.unpack("!I",socket.inet_aton(ipaddr))[0]

    @staticmethod
    def int2ip(intaddr):
        return socket.inet_ntoa(struct.pack("!I",intaddr))

    def pidof(self,prog,default=None):
        _allprogs = re.findall("(\w+)\s+(\d+)",self._run_prog("ps ax -c -o command,pid"))
        return int(dict(_allprogs).get(prog,default))

    def _config_reader(self,config=""):
        _config = ELementTree.parse("/conf/config.xml")
        _root = _config.getroot()
        return etree_to_dict(_root).get("opnsense",{})

    @staticmethod
    def get_common_name(certrdn):
        try:
            return next(filter(lambda x: x.oid == x509.oid.NameOID.COMMON_NAME,certrdn)).value
        except:
            return "fail"

    def _certificate_parser(self):
        self._certificate_timestamp = time.time()
        self._certificate_store = {}
        for _cert in self._config_reader().get("cert"):
            try:
                _certpem = base64.b64decode(_cert.get("crt"))
                _x509cert = x509.load_pem_x509_certificate(_certpem,crypto_default_backend())
                _cert["not_valid_before"]   = _x509cert.not_valid_before.timestamp()
                _cert["not_valid_after"]    = _x509cert.not_valid_after.timestamp()
                _cert["serial"]             = _x509cert.serial_number
                _cert["common_name"]        = self.get_common_name(_x509cert.subject)
                _cert["issuer"]             = self.get_common_name(_x509cert.issuer)
            except:
                pass
            self._certificate_store[_cert.get("refid")] = _cert
            
    def _get_certificate(self,refid):
        if time.time() - self._certificate_timestamp > 3600:
            self._certificate_parser()
        return self._certificate_store.get(refid)

    def _get_certificate_by_cn(self,cn,caref=None):
        if time.time() - self._certificate_timestamp > 3600:
            self._certificate_parser()
        if caref:
            _ret = filter(lambda x: x.get("common_name") == cn and x.get("caref") == caref,self._certificate_store.values())
        else:
            _ret = filter(lambda x: x.get("common_name") == cn,self._certificate_store.values())
        try:
            return next(_ret)
        except StopIteration:
            return {}

    def get_opnsense_interfaces(self):
        _ifs = {}
        #pprint(self._config_reader().get("interfaces"))
        #sys.exit(0)
        for _name,_interface in self._config_reader().get("interfaces",{}).items():
            if _interface.get("enable") != "1":
                continue
            _desc = _interface.get("descr")
            _ifs[_interface.get("if","_")] = _desc if _desc else _name.upper()
        return _ifs

    def check_firmware(self):
        if self._info.get("os_version") != self._info.get("latest_version"):
            return ["1 Firmware update_available=1 Version {os_version} ({latest_version} available)".format(**self._info)]
        return ["0 Firmware update_available=0 Version {os_version}".format(**self._info)]
        
    def check_net(self):
        _opnsense_ifs = self.get_opnsense_interfaces()
        _mapdict = {
            "line rate"                 : ("speed", lambda x: int(int(x.split(" ")[0])/1000/1000)),
            "input errors"              : ("ierror", lambda x: x),
            "output errors"             : ("oerror", lambda x: x),
            "packets received"          : ("ipackets", lambda x: x),
            "packets transmitted"       : ("opackets", lambda x: x),
            "bytes received"            : ("rx", lambda x: x),
            "bytes transmitted"         : ("tx", lambda x: x),
            "collisions"                : ("collissions", lambda x: x),
        }
        _now = int(time.time())
        _ret = ["<<<statgrab_net>>>"]
        #_interface_status = dict(re.findall("^(\w+):.*?(UP|DOWN)",subprocess.check_output("ifconfig",encoding="utf-8"),re.M))
        _interface_status = dict(
            map(lambda x: (x[0],(x[1:])),
                re.findall("^(?P<iface>\w+):.*?(?P<operstate>UP|DOWN).*?\n(?:\s+(?:media:.*?(?P<speed>\d+).*?\<(?P<duplex>.*?)\>|).*?\n)*",
                subprocess.check_output("ifconfig",encoding="utf-8"),re.M)
            )
        )
        _interface_data = self._run_prog("/usr/local/sbin/ifinfo")
        for _interface in re.finditer("^Interface\s(\w+).*?:\n((?:\s+\w+.*?\n)*)",_interface_data,re.M):
            _iface, _data = _interface.groups()
            _ifconfig = _interface_status.get(_iface,("","",""))
            _name = _opnsense_ifs.get(_iface)
            if not _name:
                continue
            _ifacedict = {
                "interface_name"    : _name,
                "duplex"            : _ifconfig[2] if _ifconfig[2] else "unknown",
                "systime"           : _now,
                "up"                : str(bool(_ifconfig[0] == "UP")).lower()
            }
            for _key,_val in re.findall("^\s+(.*?):\s(.*?)$",_data,re.M):
                _map = _mapdict.get(_key)
                if not _map:
                    continue
                _ifacedict[_map[0]] = _map[1](_val)
            
            for _key,_val in _ifacedict.items():
                _ret.append(f"{_iface}.{_key} {_val}")
        return _ret

    def check_dhcp(self):
        _ret = ["<<<isc_dhcpd>>>"]
        _ret.append("[general]\nPID: {0}".format(self.pidof("dhcpd",-1)))
        
        _dhcpleases = open("/var/dhcpd/var/db/dhcpd.leases","r").read()
        ## FIXME 
        #_dhcpleases_dict = dict(map(lambda x: (self.ip2int(x[0]),x[1]),re.findall(r"lease\s(?P<ipaddr>[0-9.]+)\s\{.*?.\n\s+binding state\s(?P<state>\w+).*?\}",_dhcpleases,re.DOTALL)))
        _dhcpleases_dict = dict(re.findall(r"lease\s(?P<ipaddr>[0-9.]+)\s\{.*?.\n\s+binding state\s(?P<state>active).*?\}",_dhcpleases,re.DOTALL))
        _dhcpconf = open("/var/dhcpd/etc/dhcpd.conf","r").read()
        _ret.append("[pools]")
        for _subnet in re.finditer(r"subnet\s(?P<subnet>[0-9.]+)\snetmask\s(?P<netmask>[0-9.]+)\s\{.*?(?:pool\s\{.*?\}.*?)*}",_dhcpconf,re.DOTALL):
            #_cidr = bin(self.ip2int(_subnet.group(2))).count("1")
            #_available = 0
            for _pool in re.finditer("pool\s\{.*?range\s(?P<start>[0-9.]+)\s(?P<end>[0-9.]+).*?\}",_subnet.group(0),re.DOTALL):
                #_start,_end = self.ip2int(_pool.group(1)), self.ip2int(_pool.group(2))
                #_ips_in_pool = filter(lambda x: _start < x[0] < _end,_dhcpleases_dict.items())
                #pprint(_dhcpleases_dict)
                #pprint(sorted(list(map(lambda x: (self._int2ip(x[0]),x[1]),_ips_in_pool))))
                #_available += (_end - _start)
                _ret.append("{0}\t{1}".format(_pool.group(1),_pool.group(2)))
            
            #_ret.append("DHCP_{0}/{1} {2}".format(_subnet.group(1),_cidr,_available))
        
        _ret.append("[leases]")
        for _ip in sorted(_dhcpleases_dict.keys()):
            _ret.append(_ip)
        return _ret

    def check_openvpn(self):
        _ret = [""]
        _cfr = self._config_reader().get("openvpn")
        if type(_cfr) != dict:
            return _ret
        try:
            _monitored_clients = dict(map(lambda x: (x.get("common_name").upper(),dict(x,current=[])),_cfr.get("openvpn-csc")))
        except:
            _monitored_clients = {}
        _now = time.time()
        for _server in _cfr.get("openvpn-server",[]):
            _server["name"] = _server.get("description") if _server.get("description") else "OpenVPN_{protocoll}_{local_port}".format(**_server)
            _caref = _server.get("caref")
            if not _server.get("maxclients"):
                _max_clients = ipaddress.IPv4Network(_server.get("tunnel_network")).num_addresses -2
                if _server.get("topology_subnet") != "yes":
                    _max_clients = int(_max_clients/4)
                _server["maxclients"] = _max_clients

            _server_cert = self._get_certificate(_server.get("certref"))
            _server["expiredate"] = "no certificate found"
            if _server_cert:
                _notvalidafter = _server_cert.get("not_valid_after")
                _server["expiredays"] = int((_notvalidafter - _now) / 86400)
                _server["expiredate"] = time.strftime("Cert Expire: %d.%m.%Y",time.localtime(_notvalidafter))
            try:
                _unix = "/var/etc/openvpn/server{vpnid}.sock".format(**_server)
                _sock = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                try:
                    _sock.connect(_unix)
                    _sock.send("status 2\n".encode("utf-8"))
                    _data = ""
                    while True:
                        _socket_data = _sock.recv(4096).decode("utf-8")
                        if _socket_data:
                            _data += _socket_data
                        if _socket_data.find("\nEND\r\n") > -1:
                            break
                    _number_of_clients = 0
                    _now = int(time.time())
                    for _client_match in re.finditer("^CLIENT_LIST,(.*?)$",_data,re.M):
                        _number_of_clients += 1
                        _client_raw = _client_match.group(1).split(",")
                        _client = {
                            "server"         : _server.get("name"),
                            "common_name"    : _client_raw[0],
                            "remote_ip"      : _client_raw[1].split(":")[0],
                            "vpn_ip"         : _client_raw[2],
                            "vpn_ipv6"       : _client_raw[3],
                            "bytes_received" : int(_client_raw[4]),
                            "bytes_sent"     : int(_client_raw[5]),
                            "uptime"         : _now - int(_client_raw[7]),
                            "username"       : _client_raw[8] if _client_raw[8] != "UNDEF" else _client_raw[0],
                            "clientid"       : int(_client_raw[9]),
                            "cipher"         : _client_raw[11].strip("\r\n")
                        }
                        if _client_raw[0].upper() in _monitored_clients:
                            _monitored_clients[_client_raw[0].upper()]["current"].append(_client)
                finally:
                    _server["status"] = 0
                    _sock.close()
                if _server["expiredays"] < 61:
                    _server["status"] = 2 if _server["expiredays"] < 31 else 1
                else:
                    _server["expiredate"] = "\\n" + _server["expiredate"]

                _server["clientcount"] = _number_of_clients
                _ret.append('{status} "OpenVPN Server: {name}" connections_ssl_vpn={clientcount};;{maxclients}|expiredays={expiredays} {clientcount}/{maxclients} Connections Port:{local_port}/{protocol} {expiredate}'.format(**_server))
            except:
                _server["status"] = 2
                _ret.append('2 "OpenVPN Server: {name}" connections_ssl_vpn=0;;{maxclients}|expiredays={expiredays} Server down Port:{local_port}/{protocol} {expiredate}'.format(**_server))

        for _client in _monitored_clients.values():
            _current_conn = _client.get("current",[])
            if not _client.get("description"):
                _client["description"] = _client.get("common_name")
            _client["expiredays"] = 0
            _client["expiredate"] = "no certificate found"
            _cert = self._get_certificate_by_cn(_client.get("common_name"))
            if _cert:
                _notvalidafter = _cert.get("not_valid_after")
                _client["expiredays"] = int((_notvalidafter - _now) / 86400)
                _client["expiredate"] = time.strftime("Cert Expire: %d.%m.%Y",time.localtime(_notvalidafter))
                if _client["expiredays"] < 61:
                    _client["status"] = 2 if _client["expiredays"] < 31 else 1
                else:
                    _client["expiredate"] = "\\n" + _client["expiredate"]

            if _current_conn:
                _client["uptime"] = max(map(lambda x: x.get("uptime"),_current_conn))
                _client["count"] = len(_current_conn)
                _client["bytes_received"] = sum(map(lambda x: x.get("bytes_received"),_current_conn))
                _client["bytes_sent"] = sum(map(lambda x: x.get("bytes_sent"),_current_conn))
                _client["longdescr"] = ""
                for _conn in _current_conn:
                    _client["longdescr"] += "Server:{server} {remote_ip}->{vpn_ip} {cipher} ".format(**_conn)
                _client["status"] = 0
                _ret.append('{status} "OpenVPN Client: {description}" uptime={uptime}|connections_ssl_vpn={count}|net_data_recv={bytes_received}|net_data_sent={bytes_sent}|expiredays={expiredays} {longdescr} {expiredate}'.format(**_client))
            else:
                _ret.append('2 "OpenVPN Client: {description}" uptime=0|connections_ssl_vpn=0|net_data_recv=0|net_data_sent=0|expiredays={expiredays} Nicht verbunden {expiredate}'.format(**_client))
        return _ret

    def check_df(self):
        _ret = ["<<<df>>>"]
        _ret += self._run_prog("df -kTP -t ufs").split("\n")[1:]
        return _ret

    def check_zfs(self):
        _ret = ["<<<zfsget>>>"]
        _ret.append(self._run_prog("zfs get -t filesystem,volume -Hp name,quota,used,avail,mountpoint,type"))
        _ret.append("[df]")
        _ret.append(self._run_prog("df -kP -t zfs"))
        _ret.append("<<<zfs_arc_cache>>>")
        _ret.append(self._run_prog("sysctl -q kstat.zfs.misc.arcstats").replace("kstat.zfs.misc.arcstats.","").strip())
        return _ret

    def check_mounts(self):
        _ret = ["<<<mounts>>>"]
        _ret.append(self._run_prog("mount -p -t ufs").strip())
        return _ret

    def check_cpu(self):
        _ret = ["<<<cpu>>>"]
        _loadavg = self._run_prog("sysctl -n vm.loadavg").strip("{} \n")
        _proc = self._run_prog("top -b -n 1").split("\n")[1].split(" ")
        _proc = "{0}/{1}".format(_proc[3],_proc[0])
        _lastpid = self._run_prog("sysctl -n kern.lastpid").strip(" \n")
        _ncpu = self._run_prog("sysctl -n hw.ncpu").strip(" \n")
        _ret.append(f"{_loadavg} {_proc} {_lastpid} {_ncpu}")
        return _ret

    def check_netctr(self):
        _ret = ["<<<netctr>>>"]
        _out = self._run_prog("netstat -inb")
        for _line in re.finditer("^(?!Name|lo|plip)(?P<iface>\w+)\s+(?P<mtu>\d+).*?Link.*?\s+.*?\s+(?P<inpkts>\d+)\s+(?P<inerr>\d+)\s+(?P<indrop>\d+)\s+(?P<inbytes>\d+)\s+(?P<outpkts>\d+)\s+(?P<outerr>\d+)\s+(?P<outbytes>\d+)\s+(?P<coll>\d+)$",_out,re.M):
            _ret.append("{iface} {inbytes} {inpkts} {inerr} {indrop} 0 0 0 0 {outbytes} {outpkts} {outerr} 0 0 0 0 0".format(**_line.groupdict()))
        return _ret

    def check_ntp(self):
        _ret = ["<<<ntp>>>"]
        for _line in self._run_prog("ntpq -np").split("\n")[2:]:
            if _line.strip():
                _ret.append("{0} {1}".format(_line[0],_line[1:]))
        return _ret
        

    def check_tcp(self):
        _ret = ["<<<tcp_conn_stats>>>"]
        _out = self._run_prog("netstat -na")
        counts = Counter(re.findall("ESTABLISHED|LISTEN",_out))
        for _key,_val in counts.items():
            _ret.append(f"{_key} {_val}")
        return _ret

    def check_ps(self):
        _ret = ["<<<ps>>>"]
        _out = self._run_prog("ps ax -o state,user,vsz,rss,pcpu,command")
        for _line in re.finditer("^(?P<stat>\w+)\s+(?P<user>\w+)\s+(?P<vsz>\d+)\s+(?P<rss>\d+)\s+(?P<cpu>[\d.]+)\s+(?P<command>.*)$",_out,re.M):
            _ret.append("({user},{vsz},{rss},{cpu}) {command}".format(**_line.groupdict()))
        return _ret
        

    def check_uptime(self):
        _ret = ["<<<uptime>>>"]
        _uptime_sec = time.time() - int(self._run_prog("sysctl -n kern.boottime").split(" ")[3].strip(" ,"))
        _idle_sec = re.findall("(\d+):[\d.]+\s+\[idle\]",self._run_prog("ps axw"))[0]
        _ret.append(f"{_uptime_sec} {_idle_sec}")
        return _ret

    def _run_prog(self,cmdline="",*args,shell=False):
        if cmdline:
            args = list(args) + shlex.split(cmdline,posix=True)
        try:
            return subprocess.check_output(args,encoding="utf-8",shell=shell)
        except subprocess.CalledProcessError as e:
            return ""


class checkmk_server(TCPServer,checkmk_checker):
    def __init__(self,port,pidfile,user,**kwargs):
        self.pidfile = pidfile
        self._mutex = threading.Lock()
        self.user = pwd.getpwnam(user)
        self.allow_reuse_address = True
        TCPServer.__init__(self,("",port),checkmk_handler,bind_and_activate=False)

    def _change_user(self):
        _, _, _uid, _gid, _, _, _ = self.user
        if os.getuid() != _uid:
            os.setgid(_gid)
            os.setuid(_uid)

    def server_start(self):
        sys.stderr.write("starting checkmk_agent\n")
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGHUP, self._signal_handler)
        sys.stderr.flush()
        self._change_user()
        try:
            self.server_bind()
            self.server_activate()
        except:
            self.server_close()
            raise
        try:
            self.serve_forever()
        except KeyboardInterrupt:
            sys.stdout.flush()
            sys.stdout.write("\n")
            pass

    def _signal_handler(self,signum,*args):
        if signum in (signal.SIGTERM,signal.SIGINT):
            sys.stderr.write("stopping checkmk_agent\n")
            threading.Thread(target=self.shutdown,name='shutdown').start()
            sys.exit(0)
        sys.stderr.write("checkmk_agent running\n")
        sys.stderr.flush()

    def daemonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                ## first parent
                sys.exit(0)
        except OSError as e:
            print("Fork failed")
            sys.exit(1)
        os.chdir("/")
        os.setsid()
        os.umask(0)
        try:
            pid = os.fork()
            if pid > 0:
                ## second
                sys.exit(0)
        except OSError as e:
            print("Fork 2 failed")
            sys.exit(1)
        sys.stdout.flush()
        sys.stderr.flush()
        self._redirect_stream(sys.stdin,None)
        self._redirect_stream(sys.stdout,None)
        #self._redirect_stream(sys.stderr,None)
        with open(self.pidfile,"wt") as _pidfile:
            _pidfile.write(str(os.getpid()))
        os.chown(self.pidfile,self.user[2],self.user[3])
        try:
            self.server_start()
        finally:
            try:
                os.remove(self.pidfile)
            except:
                pass
        
    @staticmethod
    def _redirect_stream(system_stream,target_stream):
        if target_stream is None:
            target_fd = os.open(os.devnull, os.O_RDWR)
        else:
            target_fd = target_stream.fileno()
        os.dup2(target_fd, system_stream.fileno())

    def __del__(self):
        pass ## todo

if __name__ == "__main__":
    import argparse
    _ = lambda x: x
    _parser = argparse.ArgumentParser(f"checkmk_agent for opnsense\nVersion: {__VERSION__}\n##########################################\n")
    _parser.add_argument("--port",type=int,default=6556,
        help=_("Port checkmk_agent listen"))
    _parser.add_argument("--start",action="store_true",
        help=_(""))
    _parser.add_argument("--stop",action="store_true",
        help=_(""))
    _parser.add_argument("--nodaemon",action="store_true",
        help=_(""))
    _parser.add_argument("--status",action="store_true",
        help=_(""))
    _parser.add_argument("--user",type=str,default="root",
        help=_(""))
    _parser.add_argument("--pidfile",type=str,default="/var/run/checkmk_agent.pid",
        help=_(""))
    _parser.add_argument("--debug",action="store_true",
        help=_("debug Ausgabe"))
    args = _parser.parse_args()
    _server = checkmk_server(**args.__dict__)
    _pid = None
    try:
        with open(args.pidfile,"rt") as _pidfile:
            _pid = int(_pidfile.read())
    except (FileNotFoundError,IOError):
        _out = subprocess.check_output(["sockstat", "-l", "-p", str(args.port),"-P", "tcp"],encoding=sys.stdout.encoding)
        try:
            _pid = int(re.findall("\s(\d+)\s",_out.split("\n")[1])[0])
        except (IndexError,ValueError):
            pass
    if args.start:
        if _pid:
            try:
                os.kill(_pid,0)
            except OSError:
                pass
            else:
                sys.stderr.write(f"allready running with pid {_pid}")
                sys.exit(1)
        _server.daemonize()

    elif args.status:
        if not _pid:
            sys.stderr.write("Not running\n")
        else:
            os.kill(int(_pid),signal.SIGHUP)
    elif args.stop:
        if not _pid:
            sys.stderr.write("Not running\n")
            sys.exit(1)
        os.kill(int(_pid),signal.SIGTERM)

    elif args.debug:
        print(_server.do_checks())
    elif args.nodaemon:
        _server.server_start()
    else:
#        _server.server_start()
## default start daemon
        if _pid:
            try:
                os.kill(_pid,0)
            except OSError:
                pass
            else:
                sys.stderr.write(f"allready running with pid {_pid}")
                sys.exit(1)
        _server.daemonize()

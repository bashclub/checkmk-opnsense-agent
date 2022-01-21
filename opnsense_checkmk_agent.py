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

__VERSION__ = "0.64"

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
import traceback
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
    _datastore_mutex = threading.RLock()
    _datastore = object_dict()
    def do_checks(self):
        self._getosinfo()
        _errors = []
        _lines = ["<<<check_mk>>>"]
        _lines.append("AgentOS: {os}".format(**self._info))
        _lines.append(f"Version: {__VERSION__}")
        _lines.append("Hostname: {hostname}".format(**self._info))
        for _check in dir(self):
            if _check.startswith("check_"):
                try:
                    _lines += getattr(self,_check)()
                except:
                    _errors.append(traceback.format_exc())
        _lines.append("<<<local:sep(0)>>>")
        for _check in dir(self):
            if _check.startswith("checklocal_"):
                try:
                    _lines += getattr(self,_check)()
                except:
                    _errors.append(traceback.format_exc())
        _lines.append("")
        sys.stderr.write("\n".join(_errors))
        sys.stderr.flush()
        return "\n".join(_lines)

    def _get_storedata(self,section,key):
        with self._datastore_mutex:
            return self._datastore.get(section,{}).get(key)
    def _set_storedata(self,section,key,value):
        with self._datastore_mutex:
            if section not in self._datastore:
                self._datastore[section] = object_dict()
            self._datastore[section][key] = value

    def _getosinfo(self):
        _info = json.load(open("/usr/local/opnsense/version/core","r"))
        _changelog = json.load(open("/usr/local/opnsense/changelog/index.json","r"))
        try:
            _latest_firmware = list(filter(lambda x: x.get("series") == _info.get("product_series"),_changelog))[-1]
            _current_firmware = list(filter(lambda x: x.get("version") == _info.get("product_version").split("_")[0],_changelog))[0]
            _current_firmware["age"] = int(time.time() - time.mktime(time.strptime(_current_firmware.get("date"),"%B %d, %Y")))
        except:
            raise
            _lastest_firmware = {}
            _current_firmware = {}
        self._info = {
            "os"                : _info.get("product_name"),
            "os_version"        : _info.get("product_version"),
            "version_age"      : _current_firmware.get("age",0),
            "product_series"    : _info.get("product_series"),
            "latest_version"    : _latest_firmware.get("version"),
            "latest_date"       : _latest_firmware.get("date"),
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
            return next(filter(lambda x: x.oid == x509.oid.NameOID.COMMON_NAME,certrdn)).value.strip()
        except:
            return str(certrdn)

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

    def get_opnsense_ipaddr(self):
        try:
            _ret = {}
            for _if,_ip,_mask in re.findall("^([\w_]+):\sflags=(?:8943|8051|8043).*?inet\s([\d.]+)\snetmask\s0x([a-f0-9]+)",subprocess.check_output("ifconfig",encoding="utf-8"),re.DOTALL | re.M):
                _ret[_if] = "{0}/{1}".format(_ip,str(bin(int(_mask,16))).count("1"))
            return _ret
        except:
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

        try: 
            _wgserver = self._config_reader().get("OPNsense").get("wireguard").get("server").get("servers").get("server")
            if type(_wgserver) == dict:
                _wgserver = [_wgserver]
            _ifs.update(
                dict(
                    map(
                        lambda x: ("wg{}".format(x.get("instance")),"Wireguard_{}".format(x.get("name").strip().replace(" ","_"))),
                        _wgserver
                    )
                )
            )
        except:
            pass
        return _ifs

    def checklocal_firmware(self):
        if self._info.get("os_version") != self._info.get("latest_version"):
            return ["1 Firmware update_available=1|age={version_age} Version {os_version} ({latest_version} available {latest_date})".format(**self._info)]
        return ["0 Firmware update_available=0|age={version_age} Version {os_version}".format(**self._info)]
        
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

    @staticmethod
    def _read_from_openvpnsocket(vpnsocket,cmd):
        _sock = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            _sock.connect(vpnsocket)
            assert (_sock.recv(4096).decode("utf-8")).startswith(">INFO")
            cmd = cmd.strip() + "\n"
            _sock.send(cmd.encode("utf-8"))
            _data = ""
            while True:
                _socket_data = _sock.recv(4096).decode("utf-8")
                _data += _socket_data
                if _data.strip().endswith("END") or _data.strip().startswith("SUCCESS:") or _data.strip().startswith("ERROR:"):
                    break
            return _data
        finally:
            if _sock:
                _sock.send("quit\n".encode("utf-8"))
            _sock.close()
            _sock = None
        return ""

    def _get_openvpn_traffic(self,interface,totalbytesin,totalbytesout):
        _hist_data = self._get_storedata("openvpn",interface)
        _slot = int(time.time())
        _slot -= _slot%60
        _hist_slot = 0
        _traffic_in = _traffic_out = 0
        if _hist_data:
            _hist_slot,_hist_bytesin, _hist_bytesout = _hist_data
            _traffic_in = int(totalbytesin -_hist_bytesin) / max(1,_slot - _hist_slot)
            _traffic_out = int(totalbytesout - _hist_bytesout) /  max(1,_slot - _hist_slot)
        if _hist_slot != _slot:
            self._set_storedata("openvpn",interface,(_slot,totalbytesin,totalbytesout))
        return _traffic_in,_traffic_out

    @staticmethod
    def _get_dpinger_gateway(gateway):
        _path = "/var/run/dpinger_{0}.sock".format(gateway)
        if os.path.exists(_path):
            _sock = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                _sock.connect(_path)
                _data = _sock.recv(1024).decode("utf-8").strip()
                _name, _rtt, _rttsd, _loss = re.findall("(\w+)\s(\d+)\s(\d+)\s(\d+)$",_data)[0]
                assert _name.strip() == gateway
                return int(_rtt)/1000.0,int(_rttsd)/1000.0, int(_loss)
            except:
                raise
        return -1,-1,-1

    def checklocal_gateway(self):
        _ret = []
        _gateway_items = self._config_reader().get("gateways").get("gateway_item",[])
        if type(_gateway_items) != list:
            _gateway_items = [_gateway_items] if _gateway_items else []
        _interfaces = self._config_reader().get("interfaces",{})
        _ipaddresses = self.get_opnsense_ipaddr()
        for _gateway in _gateway_items:
            if type(_gateway.get("descr")) != str:
                _gateway["descr"] = _gateway.get("name")
            if _gateway.get("monitor_disable") == "1" or _gateway.get("disabled") == "1":
                continue
            _interface = _interfaces.get(_gateway.get("interface"),{})
            _gateway["realinterface"] = _interface.get("if")
            if _gateway.get("ipprotocol") == "inet":
                _gateway["ipaddr"] = _ipaddresses.get(_interface.get("if"))
            else:
                _gateway["ipaddr"] = ""
            _gateway["rtt"], _gateway["rttsd"], _gateway["loss"] = self._get_dpinger_gateway(_gateway.get("name"))
            _gateway["status"] = 0
            if _gateway.get("loss") > 0 or _gateway.get("rtt") > 100:
                _gateway["status"] = 1
            if _gateway.get("loss") > 90 or _gateway.get("loss") == -1:
                _gateway["status"] = 2

            _ret.append("{status} \"Gateway {descr}\" rtt={rtt}|rttsd={rttsd}|loss={loss} Gateway on Interface: {realinterface} {ipaddr}".format(**_gateway))
        return _ret

    def checklocal_openvpn(self):
        _ret = []
        _cfr = self._config_reader().get("openvpn")
        if type(_cfr) != dict:
            return _ret

        _cso = _cfr.get("openvpn-csc")
        _monitored_clients = {}
        if type(_cso) == dict:
            _cso = [_cso]
        if type(_cso) == list:
            _monitored_clients = dict(map(lambda x: (x.get("common_name").upper(),dict(x,current=[])),_cso))
            
        _now = time.time()
        _vpnclient = _cfr.get("openvpn-client",[])
        _vpnserver = _cfr.get("openvpn-server",[])
        if type(_vpnserver) != list:
            _vpnserver = [_vpnserver] if _vpnserver else []
        if type(_vpnclient) != list:
            _vpnclient = [_vpnclient] if _vpnclient else []
        for _server in _vpnserver + _vpnclient:
            ## server_tls, p2p_shared_key p2p_tls
            _server["name"] = _server.get("description") if _server.get("description").strip() else "OpenVPN_{protocoll}_{local_port}".format(**_server)

            _caref = _server.get("caref")
            _server_cert = self._get_certificate(_server.get("certref"))
            _server["status"] = 3
            _server["expiredays"] = 0
            _server["expiredate"] = "no certificate found"
            if _server_cert:
                _notvalidafter = _server_cert.get("not_valid_after")
                _server["expiredays"] = int((_notvalidafter - _now) / 86400)
                _server["expiredate"] = time.strftime("Cert Expire: %d.%m.%Y",time.localtime(_notvalidafter))
                if _server["expiredays"] < 61:
                    _server["status"] = 2 if _server["expiredays"] < 31 else 1
                else:
                    _server["expiredate"] = "\\n" + _server["expiredate"]

            _server["type"] = "server" if _server.get("local_port") else "client"
            if _server.get("mode") in ("p2p_shared_key","p2p_tls"):
                _unix = "/var/etc/openvpn/{type}{vpnid}.sock".format(**_server)
                try:
                    
                    _server["bytesin"], _server["bytesout"] = self._get_openvpn_traffic(
                        "SRV_{name}".format(**_server),
                        *(map(lambda x: int(x),re.findall("bytes\w+=(\d+)",self._read_from_openvpnsocket(_unix,"load-stats"))))
                    )
                    _laststate = self._read_from_openvpnsocket(_unix,"state 1").strip().split("\r\n")[-2]
                    _timestamp, _server["connstate"], _data = _laststate.split(",",2)
                    if _server["connstate"] == "CONNECTED":
                        _data = _data.split(",")
                        _server["vpn_ipaddr"] = _data[1]
                        _server["remote_ipaddr"] = _data[2]
                        _server["remote_port"] = _data[3]
                        _server["source_addr"] = _data[4]
                        _server["status"] = 0 if _server["status"] == 3 else _server["status"]
                        _ret.append('{status} "OpenVPN Connection: {name}" connections_ssl_vpn=1;;|if_in_octets={bytesin}|if_out_octets={bytesout}|expiredays={expiredays} Connected {remote_ipaddr}:{remote_port} {vpn_ipaddr} {expiredate}\Source IP: {source_addr}'.format(**_server))
                    else:
                        if _server["type"] == "client":
                            _server["status"] = 2
                            _ret.append('{status} "OpenVPN Connection: {name}" connections_ssl_vpn=0;;|if_in_octets={bytesin}|if_out_octets={bytesout}|expiredays={expiredays} {connstate} {expiredate}'.format(**_server))
                        else:
                            _server["status"] = 1 if _server["status"] != 2 else 2
                            _ret.append('{status} "OpenVPN Connection: {name}" connections_ssl_vpn=0;;|if_in_octets={bytesin}|if_out_octets={bytesout}|expiredays={expiredays} waiting on Port {local_port}/{protocol} {expiredate}'.format(**_server))
                except:
                    _ret.append('2 "OpenVPN Connection: {name}" connections_ssl_vpn=0;;|expiredays={expiredays}|if_in_octets=0|if_out_octets=0 Server down Port:/{protocol} {expiredate}'.format(**_server))
                    raise
            else:
                if not _server.get("maxclients"):
                    _max_clients = ipaddress.IPv4Network(_server.get("tunnel_network")).num_addresses -2
                    if _server.get("topology_subnet") != "yes":
                        _max_clients = max(1,int(_max_clients/4)) ## p2p
                    _server["maxclients"] = _max_clients
                try:
                    _unix = "/var/etc/openvpn/{type}{vpnid}.sock".format(**_server)
                    try:
                        
                        _server["bytesin"], _server["bytesout"] = self._get_openvpn_traffic(
                            "SRV_{name}".format(**_server),
                            *(map(lambda x: int(x),re.findall("bytes\w+=(\d+)",self._read_from_openvpnsocket(_unix,"load-stats"))))
                        )
                        _server["status"] = 0 if _server["status"] == 3 else _server["status"]
                    except:
                        _server["bytesin"], _server["bytesout"] = 0,0
                        raise
                    
                    _number_of_clients = 0
                    _now = int(time.time())
                    _response = self._read_from_openvpnsocket(_unix,"status 2")
                    for _client_match in re.finditer("^CLIENT_LIST,(.*?)$",_response,re.M):
                        _number_of_clients += 1
                        _client_raw = list(map(lambda x: x.strip(),_client_match.group(1).split(",")))
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
                        if _client["username"].upper() in _monitored_clients:
                            _monitored_clients[_client["username"].upper()]["current"].append(_client)

                    _server["clientcount"] = _number_of_clients
                    _ret.append('{status} "OpenVPN Server: {name}" connections_ssl_vpn={clientcount};;{maxclients}|if_in_octets={bytesin}|if_out_octets={bytesout}|expiredays={expiredays} {clientcount}/{maxclients} Connections Port:{local_port}/{protocol} {expiredate}'.format(**_server))
                except:
                    _ret.append('2 "OpenVPN Server: {name}" connections_ssl_vpn=0;;{maxclients}|expiredays={expiredays}|if_in_octets=0|if_out_octets=0| Server down Port:{local_port}/{protocol} {expiredate}'.format(**_server))

        for _client in _monitored_clients.values():
            _current_conn = _client.get("current",[])
            if not _client.get("description"):
                _client["description"] = _client.get("common_name")
            _client["description"] = _client["description"].strip(" \r\n")
            _client["expiredays"] = 0
            _client["expiredate"] = "no certificate found"
            _client["status"] = 0
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
                _client["bytes_received"], _client["bytes_sent"] = self._get_openvpn_traffic(
                    "CL_{description}".format(**_client),
                    sum(map(lambda x: x.get("bytes_received"),_current_conn)),
                    sum(map(lambda x: x.get("bytes_sent"),_current_conn))
                )
                
                _client["longdescr"] = ""
                for _conn in _current_conn:
                    _client["longdescr"] += "Server:{server} {remote_ip}:{vpn_ip} {cipher} ".format(**_conn)
                _ret.append('{status} "OpenVPN Client: {description}" connectiontime={uptime}|connections_ssl_vpn={count}|if_in_octets={bytes_received}|if_out_octets={bytes_sent}|expiredays={expiredays} {longdescr} {expiredate}'.format(**_client))
            else:
                _ret.append('2 "OpenVPN Client: {description}" connectiontime=0|connections_ssl_vpn=0|if_in_octets=0|if_out_octets=0|expiredays={expiredays} Nicht verbunden {expiredate}'.format(**_client))
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

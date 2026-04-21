# Deadfall

Interactive host-graph PCAP analyzer. Flask backend + d3 frontend. 
Built for offensive network assessment work.

## Run
pip install scapy flask ipwhois
python3 pcap_analyzer.py <path.pcap> [--port 5000] [--host 127.0.0.1]

## Layout
- pcap_analyzer.py     — Flask backend, PcapAnalysis class, cred extractors
- templates/index.html — single-page UI (d3 v7, no build step)
- README.md            — user-facing docs

## Design constraints
- Single-file backend, single-file frontend. Don't split into modules 
  unless there's a strong reason.
- In-memory analysis, one PCAP per process. Not multi-tenant.
- No build step on the frontend — keep using CDN d3 and inline CSS/JS.
- Plaintext vs encrypted classification lives in PLAINTEXT_PORTS / 
  ENCRYPTED_PORTS dicts at the top of pcap_analyzer.py.

## Testing
- gen_test_pcap.py (if kept) produces /tmp/test_capture.pcap with mixed 
  plaintext/encrypted traffic for smoke testing.
- Real test pcaps live in ./samples/ (gitignored).

## Known issues
- Scapy's IPv6 route enumeration crashes in some Linux containers. 
  Workaround is the rtnetlink monkeypatch at the top of pcap_analyzer.py — 
  don't remove it.

<div align="center">

# ⚡ bountyFlow
### Authorization-first web asset reconnaissance

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](#quick-start)
[![Version](https://img.shields.io/badge/version-2.1.0-18B7A0?style=for-the-badge)](#whats-inside)
[![License](https://img.shields.io/badge/license-MIT-8A2BE2?style=for-the-badge)](LICENSE)
[![Testing](https://img.shields.io/badge/tests-9%20passing-29B765?style=for-the-badge)](#quality)

**Created and maintained by [M-Abdullah-lab](https://github.com/M-Abdullah-lab)**

*Fast signal collection • Clear evidence • Responsible workflows*

</div>

> [!WARNING]
> **Authorized use only.** Run bountyFlow only against assets you own or have explicit permission to assess. Findings are observations—not proof of a vulnerability—and must be manually validated in scope.

---

## ✨ Why bountyFlow?

bountyFlow turns a target hostname into a concise, reviewable asset snapshot. It prioritizes **low-impact collection**, transparent reporting, and predictable automation over aggressive scanning.

<table>
<tr>
<td width="33%"><b>🧭 Evidence-led</b><br>Collects DNS, TLS, HTTP, registration, and technology signals in a structured format.</td>
<td width="33%"><b>⚙️ Efficient</b><br>One shared root HTTP response feeds both header analysis and technology fingerprinting.</td>
<td width="33%"><b>🛡️ Deliberate by default</b><br>TCP banner reads and UDP probes are opt-in and require an authorization acknowledgement.</td>
</tr>
</table>

## 🗂️ Contents

- [Quick start](#quick-start)
- [What’s inside](#whats-inside)
- [Command guide](#command-guide)
- [Reports](#reports)
- [Technology rules](#technology-rules)
- [Architecture](#architecture)
- [Responsible use](#responsible-use)
- [Quality](#quality)

## 🚀 Quick start

```bash
git clone https://github.com/M-Abdullah-lab/bountyFlow.git
cd bountyFlow
python -m pip install -r requirements.txt

# Read-only collection
python main.py example.com --authorized
```

> Root URLs are accepted (`https://example.com/`). Paths, credentials, query strings, and fragments are deliberately rejected to keep collection scope clear.

## 🧩 What’s inside

| Surface | What bountyFlow collects | Notes |
|---|---|---|
| 🌐 Network | IPv4, IPv6, PTR hostname | Uses system DNS resolution |
| 🧾 DNS | A, **AAAA**, MX, NS, TXT, CNAME, **CAA** | CAA helps document certificate-issuer policy |
| 🔒 TLS | Protocol, issuer, subject, validity, SANs | Wildcard SANs are highlighted as scope-review signals |
| 🧱 HTTP | Final URL, status, server metadata, security headers | Root response is fetched once and shared |
| 🔁 CORS | Origin-reflection / wildcard policy signals | One documented custom-Origin probe |
| 🏷️ Technology | Server, CMS, framework, CDN, analytics signals | Rules are editable JSON—not hard-coded |
| 📋 Registration | Registrar, lifecycle dates, name servers | Availability depends on registry/provider responses |
| 🔌 Optional TCP | Small common-port set + bounded banners | Requires `--authorized --ports` |
| 📡 Optional UDP | Minimal DNS and NTP response probes | Requires `--authorized --udp`; silence is ambiguous |

## 🧰 Command guide

### Standard asset snapshot

```bash
python main.py example.com --authorized
```

### Save into a specific directory

```bash
python main.py https://example.com --authorized --output reports/client-a
```

### Authorized TCP exposure check

```bash
python main.py example.com --authorized --ports
```

TCP checks use a small fixed port set. If a service is reachable, bountyFlow reads at most 1024 bytes; HTTP-family ports receive a minimal `HEAD /` request. It does not authenticate, enumerate content, or exploit services.

### Authorized UDP response probe

```bash
python main.py example.com --authorized --udp
```

DNS (53/udp) and NTP (123/udp) receive small protocol-shaped requests. A non-response can mean filtering, a closed port, or a service that does not respond—so it is **never** reported as “closed.”

### Terminal-only mode

```bash
python main.py example.com --authorized --no-report
```

Run `python main.py --help` to view every option.

## 📦 Reports

Each normal run creates two UTC-stamped files in `reports/`:

| File | Purpose |
|---|---|
| `target_YYYYMMDD_HHMMSSZ.json` | Complete structured data for automation, review, or ingestion |
| `target_YYYYMMDD_HHMMSSZ.txt` | Compact analyst-friendly summary |

Reports record the tool identity, version, collection timestamp, findings, and the authorization reminder. Store them according to the engagement’s data-handling rules.

## 🧠 Technology rules

Fingerprint rules live in [`modules/signatures.json`](modules/signatures.json). This makes rules easy to extend without editing application code.

```json
{
  "type": "header",
  "header": "server",
  "pattern": "nginx",
  "technology": "Nginx",
  "category": "Web Server"
}
```

Supported `type` values are `header`, `body`, and `cookie`. bountyFlow validates the JSON structure and regex syntax before it uses rules.

## 🏗️ Architecture

```text
                 ┌──────────────────┐
 target ────────▶│ Target validation │
                 └────────┬─────────┘
                          │
          ┌───────────────┼────────────────┐
          ▼               ▼                ▼
     DNS / host        TLS / WHOIS    shared HTTP context
                                             │
                                   ┌─────────┴─────────┐
                                   ▼                   ▼
                         security headers        tech detection
                                   │
                              optional CORS probe

       IPv4 resolved ──▶ optional TCP / UDP checks ──▶ JSON + TXT reports
```

## 📁 Project layout

```text
bountyFlow/
├── main.py                     # CLI, orchestration, rich terminal view
├── modules/
│   ├── http_client.py           # shared verified HTTP response context
│   ├── signatures.json          # user-editable technology rules
│   ├── dns_lookup.py            # A / AAAA / MX / NS / TXT / CNAME / CAA
│   ├── security_headers.py      # header posture and CORS policy signal
│   ├── ssl_checker.py           # certificate and wildcard SAN inspection
│   ├── tech_detector.py         # context-based fingerprinting
│   ├── whois_lookup.py          # quiet, fault-tolerant WHOIS collection
│   ├── port_scanner.py          # opt-in TCP and UDP checks
│   └── report_generator.py      # JSON and TXT reporting
├── tests/
├── reports/
└── requirements.txt
```

## 🤝 Responsible use

1. Obtain **written authorization** and stay within the approved scope.
2. Respect target rate limits, rules of engagement, and disclosure processes.
3. Use `--ports` and `--udp` only when those exact checks are approved.
4. Treat missing headers, versions, banners, and technologies as review signals—not vulnerabilities.
5. Protect collected data and remove it when the engagement’s retention policy requires it.



## 📄 License

- License: [MIT](LICENSE)

<div align="center">

**Built for clear, careful, authorized security work.**

</div>

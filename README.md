<p align="center">
  <img src="static/banner.svg" alt="Sentinel Banner" width="100%"/>
</p>

<p align="center">
  <a href="#-features"><img src="https://img.shields.io/badge/version-1.0-83B740?style=for-the-badge&logo=checkmarx&logoColor=white" alt="Version 1.0"/></a>
  <img src="https://img.shields.io/badge/python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/platform-Kali%20|%20Linux%20|%20Windows-purple?style=for-the-badge&logo=linux&logoColor=white" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-authorized%20use-red?style=for-the-badge&logo=gnuprivacyguard&logoColor=white" alt="License"/>
  <img src="https://img.shields.io/badge/interface-browser%20UI-0078D4?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Interface"/>
</p>

<p align="center">
  <i>A powerful, local browser-based web security assessment dashboard with XSS detection, SQL injection diagnostics, WAF analysis, and real-time reporting — all running on <code>127.0.0.1</code>.</i>
</p>

<img src="static/wave-divider.svg" width="100%" alt=""/>

<br/>

## 🎯 Overview

**Sentinel** is a sleek, local-only web security assessment dashboard built on top of a Python XSS scanner engine. It provides a modern, responsive browser interface for performing authorized security assessments — no desktop GUI toolkit required.

> [!WARNING]
> **Authorized assessment only.** Use only against applications you own or have explicit written permission to test. Automated results are heuristic and require manual validation.

<br/>

## ✨ Features

<table>
<tr>
<td width="50%" valign="top">

### 🛡️ XSS Assessment
- Live findings grouped by endpoint, parameter, method & type
- Search, severity/type/review filters, sorting & pagination
- Finding detail view with evidence & reproduction URLs
- Persistent review flags & session-local history
- Live findings snapshots during active scans

</td>
<td width="50%" valign="top">

### 💉 SQL Injection Diagnostics
- Opt-in module with separate authorization
- GET-only with 20-parameter cap & 4 requests per param
- Database error-signature & boolean differential checks
- Smart skipping of sensitive & state-changing routes
- SQL-only rerun without full rescan

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🔥 WAF Analysis
- 30 non-executable inert normalization diagnostics
- Passive WAF signature identification
- Records blocked / rate-limited / reflected responses
- Zero executable evasion payloads by design

</td>
<td width="50%" valign="top">

### 🔬 Reflection-Context Audit
- Inert marker injection on discovered GET parameters
- 8 context classifications (HTML, JS, CSS, JSON, etc.)
- Review-priority hints for manual investigation
- Capped at 100 GET parameter checks per run

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 📊 Dashboard & Reporting
- Nexus-inspired dark theme with lime accents
- Optional light theme toggle
- Real-time scan phase, progress & event feed
- JSON, CSV, HTML & Markdown remediation reports

</td>
<td width="50%" valign="top">

### 🔒 Security Review
- 6 HTTP security-header controls (HSTS, CSP, etc.)
- Cookie flag audit (Secure, HttpOnly, SameSite)
- DOM sink observations for manual review
- Searchable endpoint inventory (up to 500)

</td>
</tr>
</table>

<br/>

## 🚀 Quick Start

### Prerequisites

| Requirement | Details |
|:--|:--|
| **Python** | 3.8 or higher |
| **Packages** | `requests`, `beautifulsoup4`, `colorama`, `urllib3`, `dnspython` |
| **Browser** | Any modern browser |
| **OS** | Kali Linux (recommended), Linux, Windows |

### 🐧 Linux / Kali

```bash
# Clone and launch
git clone <repo-url> sentinel-v1.0
cd sentinel-v1.0

chmod +x run_gui.sh
./run_gui.sh
```

### 🪟 Windows

```batch
cd sentinel-v1.0
run_gui.bat
```

### 🐍 Virtual Environment (Recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate
./run_gui.sh
```

<br/>

> [!TIP]
> The launcher automatically installs dependencies and opens your browser at **`http://127.0.0.1:8765`**. If the browser doesn't open, navigate there manually.

<br/>

## 🏗️ Architecture

```
sentinel-v1.0/
│
├── 🖥️  web_ui.py            # HTTP server, scan orchestration & report engine
├── 🔍  xss_scanner.py       # Core XSS scanner engine & CLI
├── 📄  requirements.txt     # Python dependencies
│
├── 🌐  static/
│   └── index.html           # Responsive browser dashboard
│
├── 🧪  tests/
│   └── test_web_ui.py       # Unit tests
│
├── 🚀  run_gui.sh           # Linux/Kali launcher
├── 🚀  run_gui.bat          # Windows launcher
├── ⚙️   install_gsd_core.sh  # GSD Core installer (Linux)
├── ⚙️   install_gsd_core.bat # GSD Core installer (Windows)
│
└── 📋  subdomains.txt       # Subdomain wordlist
```

<br/>

## ⚙️ Scan Profiles

<table>
<tr>
<th>Profile</th>
<th>Speed</th>
<th>Depth</th>
<th>Best For</th>
</tr>
<tr>
<td>⚡ <b>Quick</b></td>
<td>Fast</td>
<td>Shallow</td>
<td>Rapid surface-level check</td>
</tr>
<tr>
<td>🔄 <b>Standard</b></td>
<td>Balanced</td>
<td>Moderate</td>
<td>General security assessment</td>
</tr>
<tr>
<td>🔬 <b>Deep</b></td>
<td>Thorough</td>
<td>Maximum</td>
<td>Comprehensive analysis</td>
</tr>
</table>

**Request pacing options:** `0ms` · `150ms` · `350ms` · `700ms` — helps reduce rate-limit pressure during authorized testing.

<br/>

## 🔧 Configuration

### Custom Request Headers

Add authorization headers for staging environments:

```http
Authorization: Bearer YOUR_STAGING_TOKEN
X-Environment: staging
```

> [!CAUTION]
> Do not share reports or logs containing secrets. Any header you enter is used in outgoing scanner requests.

### SQL Injection Diagnostics

SQL diagnostics are **opt-in** and require explicit authorization:

| Safeguard | Detail |
|:--|:--|
| **Scope** | GET parameters only |
| **Limit** | 20 eligible parameters, 4 requests each |
| **Pacing** | Minimum 150ms between requests |
| **Skips** | Credentials, CSRF tokens, session IDs |
| **Excludes** | State-changing routes (logout, delete, etc.) |
| **No** | POST, time-delay, UNION, enumeration, data extraction |

<br/>

## 📑 Export Formats

| Format | Contents |
|:--|:--|
| 📊 **JSON** | Full assessment data — findings, WAF, reflection audit, SQL, headers, cookies, DOM, logs |
| 📋 **CSV** | One row per grouped finding |
| 🌐 **HTML** | Standalone shareable report |
| 📝 **Markdown** | Remediation checklist for findings, headers, cookies |
| 📜 **Activity Log** | Timestamped scan event feed |

<br/>

## 🧪 Testing

```bash
# Run the full test suite
python -m unittest discover -s tests -v

# Syntax validation
python -m py_compile web_ui.py xss_scanner.py
```

<br/>

## 🛡️ Security Design Principles

<table>
<tr><td>🏠</td><td><b>Local-only</b></td><td>Binds exclusively to <code>127.0.0.1</code> — never exposed to a network</td></tr>
<tr><td>🚫</td><td><b>No evasion payloads</b></td><td>WAF diagnostics use only inert, non-executable markers</td></tr>
<tr><td>🔐</td><td><b>No data extraction</b></td><td>SQL diagnostics are heuristic — no UNION, enumeration, or file access</td></tr>
<tr><td>🍪</td><td><b>Cookie privacy</b></td><td>Cookie values are never displayed in the UI or exported reports</td></tr>
<tr><td>⏱️</td><td><b>Cooperative cancellation</b></td><td>Stop any assessment and retain partial results</td></tr>
<tr><td>📊</td><td><b>Heuristic results</b></td><td>All findings require manual validation — no proof of exploitability</td></tr>
</table>

<br/>

## 📖 Notes

- Assessment history is kept in memory for the current session (up to 12 runs)
- Recent target suggestions and review flags use browser local storage
- The HTTP security-header panel is a baseline check — a present header isn't necessarily correctly configured
- A scan with no findings does **not** prove the application is free of vulnerabilities
- WAF detection is best-effort; reverse proxies and custom rules may not be identified

<br/>

## 🤝 GSD Core Integration (Optional)

On first launch, Sentinel offers to install [GSD Core](https://github.com/open-gsd/gsd-core) — an AI-assisted spec-driven development workflow. It is **not** a scanner dependency and does not run during assessments.

```bash
# Manual install anytime
./install_gsd_core.sh      # Linux/Kali
install_gsd_core.bat       # Windows

# Requires Node.js 18+ and npm/npx
npx @opengsd/gsd-core@latest
```

<br/>

---

<p align="center">
  <img src="static/footer.svg" alt="Footer" width="100%"/>
</p>

<p align="center">
  <sub>Built with 🐍 Python · Secured by design · Local-only by default</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Created%20by-Subhajit-83B740?style=flat-square" alt="Created by Subhajit"/>
  <img src="https://img.shields.io/badge/Sentinel-v1.0-B5DC82?style=flat-square&logo=checkmarx&logoColor=white" alt="Sentinel v1.0"/>
</p>

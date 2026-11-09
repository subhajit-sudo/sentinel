# Sentinel 1.0 — Release Notes

## Initial release

Sentinel 1.0 is the first consolidated release of the web security assessment dashboard.

### Core features
- Local browser-based dashboard bound to `127.0.0.1:8765` with responsive dark/light theme.
- Quick, Standard, and Deep scan profiles with configurable crawl depth, request timeout, and cooperative request pacing.
- Live scan phase indicator, progress tracking, event feed, and summary metrics.
- Stop/cancel a running assessment and retain partial results.
- Live HTTP request counter.

### XSS assessment
- Findings grouped by endpoint, parameter, method, and XSS type with search, severity/type/review filters, sorting, and pagination.
- Finding detail view with evidence, recorded payloads, and reproduction URL.
- Persistent-in-browser finding review flags and session-local assessment history.
- Searchable endpoint inventory with discovered GET/POST parameters.

### Reflection-context audit
- Advanced inert reflection-context audit for discovered GET parameters.
- Classifies HTML text, HTML attribute, URL attribute, event-handler attribute, inline JavaScript, CSS, JSON string, and unparsed markup contexts.
- Review-priority hints; the audit does not claim exploitability.

### WAF diagnostics
- Thirty non-executable inert WAF normalization diagnostics.
- Records whether responses are blocked, rate-limited, reflected, or normalized.
- No executable WAF-evasion payloads are added by the dashboard.

### SQL injection diagnostics (opt-in)
- Separate opt-in SQL injection diagnostics panel with explicit authorization.
- GET parameters only; 20-parameter cap; four requests per parameter; 150 ms minimum pacing.
- Common database error-signature checks and paired boolean response-differential heuristics.
- Skips credential/session/CSRF/token-like parameter names and state-changing routes.
- SQL-only rerun for the latest completed assessment without requiring a full rescan.
- Discovery fallback and parameter accounting.

### Security headers and cookies
- Passive review of six HTTP security-header controls.
- Cookie flag review for Secure, HttpOnly, and SameSite attributes.
- Passive WAF signature identification.
- DOM sink observations for manual review.

### Reports and export
- JSON, CSV, standalone HTML, and activity-log exports.
- Markdown remediation plan.

### Other
- Optional custom request headers for authorized staging environments.
- GSD Core developer workflow integration (optional, first-run prompt).
- Creator: Subhajit branding in the dashboard, CLI banner, and reports.

## Validation

```bash
python -m unittest discover -s tests -v
python -m py_compile web_ui.py xss_scanner.py
```


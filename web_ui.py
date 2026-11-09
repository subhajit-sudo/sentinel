#!/usr/bin/env python3
"""Local browser UI for Sentinel's web security assessment engine.

Binds to loopback only. SQL diagnostics are opt-in, GET-only, paced, and
heuristic; the UI does not perform database enumeration or data extraction.
WAF checks use inert markers rather than executable evasion payloads.
"""
from __future__ import annotations

import base64
import csv
import io
import json
import re
import threading
import time
import unicodedata
import webbrowser
from contextlib import redirect_stdout
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urlparse, urlsplit, urlunsplit
from difflib import SequenceMatcher
from urllib.parse import unquote
from typing import Any

import requests
from xss_scanner import XSSScanner

ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"
HOST = "127.0.0.1"
PORT = 8765
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_LOCK = threading.RLock()
_STATE: dict[str, Any] = {
    "status": "ready", "phase": "Ready", "progress": 0, "target": "",
    "started_at": None, "finished_at": None, "summary": {}, "findings": [],
    "endpoints": [], "dom_sinks": [], "waf_checks": [], "reflection_audit": [], "sql_audit": [], "sql_audit_status": "disabled",
    "sql_audit_meta": {"enabled": False, "discovered_get_parameters": 0, "eligible_parameters": 0,
                        "selected_parameters": 0, "skipped_sensitive": 0, "skipped_stateful": 0,
                        "capped": 0, "requests_sent": 0},
    "sql_audit_available": False, "waf_detection": [],
    "security_headers": [], "cookie_audit": [], "http_meta": {}, "logs": [], "error": None,
    "requests_sent": 0,
}
# Kept in memory for this local server session; no target or report is sent remotely.
_HISTORY: list[dict[str, Any]] = []
_SCAN_THREAD: threading.Thread | None = None
_SCAN_CANCEL_EVENT: threading.Event | None = None
_SQL_AUDIT_THREAD: threading.Thread | None = None
_LAST_SCANNER: XSSScanner | None = None


class ScanCancelled(BaseException):
    """Internal cooperative-cancellation signal; bypasses broad Exception handlers."""


def install_scan_hooks(scanner: XSSScanner, cancel_event: threading.Event, request_delay_ms: int = 0) -> None:
    """Add cancellation and request telemetry to this scanner session."""
    original_request = scanner.session.request
    request_lock = threading.Lock()
    pacing_lock = threading.Lock()
    counter = {"total": 0}
    last_request_started = {"value": 0.0}
    delay_seconds = max(0, min(int(request_delay_ms), 2000)) / 1000.0
    scanner.request_count = 0
    scanner._cancel_event = cancel_event
    scanner.request_delay_ms = int(delay_seconds * 1000)
    scanner._request_pacing_config = {"delay_seconds": delay_seconds, "last_started": last_request_started}

    def tracked_request(method: str, url: str, **kwargs: Any) -> requests.Response:
        if cancel_event.is_set():
            raise ScanCancelled("Assessment stopped by user.")
        # Space request starts consistently across scanner worker threads. The
        # event wait remains interruptible so Stop does not wait out the delay.
        with pacing_lock:
            if cancel_event.is_set():
                raise ScanCancelled("Assessment stopped by user.")
            effective_delay = float(scanner._request_pacing_config.get("delay_seconds", delay_seconds))
            wait_for = effective_delay - (time.monotonic() - last_request_started["value"])
            if wait_for > 0 and cancel_event.wait(wait_for):
                raise ScanCancelled("Assessment stopped by user.")
            if cancel_event.is_set():
                raise ScanCancelled("Assessment stopped by user.")
            last_request_started["value"] = time.monotonic()
            with request_lock:
                counter["total"] += 1
                scanner.request_count = counter["total"]
                with _LOCK:
                    _STATE["requests_sent"] = counter["total"]
        response = original_request(method, url, **kwargs)
        if cancel_event.is_set():
            raise ScanCancelled("Assessment stopped by user.")
        return response

    # Session.get/post both call this method, so all scanner HTTP work is covered.
    scanner.session.request = tracked_request


def raise_if_cancelled(scanner: XSSScanner | None = None, event: threading.Event | None = None) -> None:
    current = event or getattr(scanner, "_cancel_event", None)
    if current is not None and current.is_set():
        raise ScanCancelled("Assessment stopped by user.")


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def add_log(message: str) -> None:
    message = re.sub(r"\x1b\[[0-9;]*m", "", str(message)).replace("\t", " ").strip()
    if not message:
        return
    message = re.sub(r"\s+", " ", message)
    if len(message) > 260:
        message = message[:257] + "..."
    with _LOCK:
        _STATE["logs"].append({"time": now_iso(), "message": message})
        _STATE["logs"] = _STATE["logs"][-220:]
        lower = message.lower()
        if "detecting waf" in lower or "waf diagnostics" in lower:
            _STATE["phase"] = "WAF diagnostics"
            _STATE["progress"] = max(_STATE["progress"], 8)
        elif "crawling" in lower or "crawl" in lower:
            _STATE["phase"] = "Endpoint discovery"
            _STATE["progress"] = max(_STATE["progress"], 25)
        elif "dom" in lower:
            _STATE["phase"] = "DOM analysis"
            _STATE["progress"] = max(_STATE["progress"], 65)
        elif "payload" in lower or "xss testing" in lower:
            _STATE["phase"] = "XSS testing"
            _STATE["progress"] = max(_STATE["progress"], 78)


class StreamWriter:
    """Capture concise scanner messages for the browser activity feed."""
    KEEP = ("[*]", "[+]", "[!]", "[-]", "WAF", "Pages visited", "SCAN COMPLETE",
            "VULNERABILITY", "POTENTIAL DOM XSS", "Total parameters", "Total test",
            "Error scanning", "No parameters", "Reflected param", "SCAN SUMMARY",
            "Crawling complete", "Found", "Testing")

    def __init__(self) -> None:
        self.buffer = ""

    def write(self, value: str) -> int:
        self.buffer += value
        while "\n" in self.buffer or "\r" in self.buffer:
            positions = [p for p in (self.buffer.find("\n"), self.buffer.find("\r")) if p >= 0]
            pos = min(positions)
            line, self.buffer = self.buffer[:pos], self.buffer[pos + 1:]
            self._emit(line)
        return len(value)

    def flush(self) -> None:
        if self.buffer.strip():
            self._emit(self.buffer)
        self.buffer = ""

    def _emit(self, line: str) -> None:
        clean = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
        if clean and any(marker.lower() in clean.lower() for marker in self.KEEP):
            add_log(clean)


def group_findings(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for raw in raw_findings:
        url = str(raw.get("url", ""))
        param = str(raw.get("param", "—"))
        method = str(raw.get("method", "—")).upper()
        xss_type = str(raw.get("type", "reflected")).lower()
        key = (url, param, method, xss_type)
        if key not in grouped:
            grouped[key] = {
                "url": url, "parameter": param, "method": method, "type": xss_type,
                "severity": str(raw.get("severity", "medium")).lower(),
                "context": str(raw.get("context", "unknown")),
                "evidence": str(raw.get("evidence") or raw.get("context") or raw.get("sink") or "Input reflection or source-to-sink pattern detected."),
                "payloads": [],
                "poc_url": str(raw.get("exploitation_url") or raw.get("encoded_url") or raw.get("full_url") or url),
                "waf_bypass": bool(raw.get("is_waf_bypass", False)),
            }
        payload = raw.get("payload")
        if payload and str(payload) not in grouped[key]["payloads"]:
            grouped[key]["payloads"].append(str(payload))
        severity = str(raw.get("severity", "medium")).lower()
        if SEVERITY_ORDER.get(severity, 9) < SEVERITY_ORDER.get(grouped[key]["severity"], 9):
            grouped[key]["severity"] = severity
        if raw.get("exploitation_url") or raw.get("encoded_url") or raw.get("full_url"):
            grouped[key]["poc_url"] = str(raw.get("exploitation_url") or raw.get("encoded_url") or raw.get("full_url"))
    return sorted(grouped.values(), key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["url"], item["parameter"]))



def passive_dom_sink_review(scanner: XSSScanner) -> list[dict[str, Any]]:
    """Collect static DOM source/sink observations without generating PoC URLs."""
    observations: list[dict[str, Any]] = []
    for url in list(scanner.visited)[:10]:
        raise_if_cancelled(scanner)
        try:
            response = scanner.session.get(url, timeout=scanner.timeout, verify=False)
            for sink in scanner._detect_dom_sinks(response.text):
                item = dict(sink)
                item["url"] = url
                observations.append(item)
        except requests.RequestException:
            continue
    scanner.dom_sinks_found = observations
    if observations:
        add_log(f"[+] Passive DOM review · {len(observations)} source/sink pattern(s) observed")
    else:
        add_log("[+] Passive DOM review · no source/sink patterns observed")
    return observations


def build_safe_waf_probes(token: str) -> list[tuple[str, str]]:
    """Return varied, inert marker representations (never executable XSS)."""
    html_marker = f'<xss-probe data-check="{token}">marker</xss-probe>'
    encoded = quote(html_marker, safe="")
    return [
        ("Plain marker", token),
        ("Inert custom element", html_marker),
        ("HTML entity delimiters", html_marker.replace("<", "&lt;").replace(">", "&gt;")),
        ("Decimal HTML entities", html_marker.replace("<", "&#60;").replace(">", "&#62;")),
        ("Hex HTML entities", html_marker.replace("<", "&#x3c;").replace(">", "&#x3e;")),
        ("URL encoding", encoded),
        ("Double URL encoding", quote(encoded, safe="")),
        ("Form-style encoding", quote_plus(html_marker, safe="")),
        ("Uppercase tag", f'<XSS-PROBE DATA-CHECK="{token}">marker</XSS-PROBE>'),
        ("Mixed-case tag", f'<XsS-PrObE data-check="{token}">marker</xSs-pRoBe>'),
        ("Attribute spacing", f'<xss-probe  data-check = "{token}">marker</xss-probe>'),
        ("Inert HTML comment", f'<!-- {token} -->'),
        ("Plain text wrapper", f'BEGIN-{token}-END'),
        ("Percent-escape case", re.sub(r"%[0-9a-f]{2}", lambda m: m.group(0).upper(), encoded)),
        ("XML escaped marker", html_marker.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")),
        ("JSON string marker", json.dumps(html_marker, ensure_ascii=True)[1:-1]),
        ("Tab/newline whitespace", f'<xss-probe\n\tdata-check="{token}">marker</xss-probe>'),
        ("Unicode fullwidth delimiters", html_marker.replace("<", "＜").replace(">", "＞")),
        ("Collapsed plain-text marker", f"BEGIN-{token[:4]}-{token[4:]}-END"),
        ("Mixed percent encoding", "%3C" + html_marker[1:-1].replace("<", "%3C").replace(">", "%3E") + "%3E"),
        ("HTML entities without semicolons", html_marker.replace("<", "&#60").replace(">", "&#62")),
        ("Hex entities without semicolons", html_marker.replace("<", "&#x3c").replace(">", "&#x3e")),
        ("Double HTML entity escaping", html_marker.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")),
        ("JSON Unicode delimiter escapes", html_marker.replace("<", r"\u003c").replace(">", r"\u003e")),
        ("Base64 inert marker text", base64.b64encode(token.encode("ascii")).decode("ascii")),
        ("XML CDATA marker", f"<![CDATA[{token}]]>"),
        ("XML comment marker", f"<!--xml:{token}-->"),
        ("Uppercase plain marker", token.upper()),
        ("Whitespace-wrapped marker", f"  \t{token}\n  "),
        ("NFC Unicode marker", unicodedata.normalize("NFC", token)),
    ]


def safe_waf_normalization_checks(scanner: XSSScanner, target: str) -> list[dict[str, Any]]:
    """Send inert marker strings to one target URL and report handling.

    These markers are not scripts, event handlers, URL schemes, or executable
    browser payloads. Results are diagnostic only and cannot prove bypass.
    """
    token = "XSSPROBE" + str(int(time.time()))[-7:]
    probes = build_safe_waf_probes(token)
    results: list[dict[str, Any]] = []
    add_log(f"[+] Running {len(probes)} non-executable WAF normalization checks")
    for label, value in probes:
        raise_if_cancelled(scanner)
        record: dict[str, Any] = {"name": label, "status": "unknown", "http_status": None, "reflected": False, "duration_ms": None}
        try:
            started = time.perf_counter()
            response = scanner.session.get(
                target, params={"__xss_waf_probe": value}, timeout=scanner.timeout,
                verify=False, allow_redirects=True,
            )
            elapsed = round((time.perf_counter() - started) * 1000)
            body = response.text[:1_500_000]
            record["http_status"] = response.status_code
            record["duration_ms"] = elapsed
            record["reflected"] = token.lower() in body.lower()
            record["final_url"] = response.url
            record["content_type"] = response.headers.get("Content-Type", "")[:120]
            record["server"] = response.headers.get("Server", "")[:100]
            record["response_bytes"] = len(response.content or b"")
            record["redirects"] = max(0, len(response.history))
            lower_body = body.lower()
            record["challenge_hints"] = [hint for hint in ("cloudflare", "access denied", "request blocked", "web application firewall", "incident id") if hint in lower_body][:3]
            if response.status_code in (403, 406, 418):
                record["status"] = "blocked"
            elif response.status_code == 429:
                record["status"] = "rate_limited"
            elif response.status_code >= 500:
                record["status"] = "server_error"
            elif record["reflected"]:
                record["status"] = "reflected"
            else:
                record["status"] = "not_reflected_or_normalized"
        except requests.RequestException as exc:
            record["status"] = "request_error"
            record["error"] = str(exc)[:180]
        results.append(record)
        with _LOCK:
            _STATE["waf_checks"] = list(results)
        add_log(f"[+] WAF check · {label}: {record['status']}" + (f" · HTTP {record['http_status']}" if record["http_status"] else ""))
        if getattr(scanner, "_cancel_event", None) is not None:
            scanner._cancel_event.wait(0.12)
        else:
            time.sleep(0.12)
    return results



class _ReflectionContextParser(HTMLParser):
    """Find inert marker occurrences in parsed HTML contexts."""

    URL_ATTRIBUTES = {"href", "src", "action", "formaction", "poster", "xlink:href"}

    def __init__(self, marker: str):
        super().__init__(convert_charrefs=True)
        self.marker = marker.casefold()
        self.contexts: list[str] = []
        self.raw_tag: str | None = None

    def _record(self, value: Any, context: str) -> None:
        if value is not None and self.marker in str(value).casefold() and context not in self.contexts:
            self.contexts.append(context)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            attr = (name or "").casefold()
            if attr.startswith("on"):
                context = "event_handler_attribute"
            elif attr in self.URL_ATTRIBUTES:
                context = "url_attribute"
            else:
                context = "html_attribute"
            self._record(value, context)
        if tag.casefold() in {"script", "style"}:
            self.raw_tag = tag.casefold()

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.casefold() in {"script", "style"}:
            self.raw_tag = None

    def handle_endtag(self, tag: str) -> None:
        if self.raw_tag == tag.casefold():
            self.raw_tag = None

    def handle_data(self, data: str) -> None:
        context = "javascript" if self.raw_tag == "script" else "css" if self.raw_tag == "style" else "html_text"
        self._record(data, context)

    def handle_comment(self, data: str) -> None:
        self._record(data, "html_comment")


def classify_reflection_contexts(body: str, marker: str, content_type: str = "") -> list[str]:
    """Classify where an inert marker is reflected; this is not an XSS proof."""
    if not marker or marker.casefold() not in (body or "").casefold():
        return []
    if "json" in (content_type or "").casefold():
        try:
            parsed = json.loads(body)
            found: list[str] = []
            def walk(value: Any) -> None:
                if isinstance(value, str) and marker.casefold() in value.casefold():
                    if "json_string" not in found:
                        found.append("json_string")
                elif isinstance(value, dict):
                    for child in value.values():
                        walk(child)
                elif isinstance(value, list):
                    for child in value:
                        walk(child)
            walk(parsed)
            if found:
                return found
        except (TypeError, ValueError):
            pass
    parser = _ReflectionContextParser(marker)
    try:
        parser.feed(body or "")
        parser.close()
    except Exception:
        pass
    contexts = list(parser.contexts)
    if not contexts:
        contexts.append("unparsed_markup")
    return contexts


def _review_priority(contexts: list[str]) -> str:
    high = {"event_handler_attribute", "javascript", "url_attribute"}
    medium = {"html_attribute", "css", "unparsed_markup"}
    if any(context in high for context in contexts):
        return "high"
    if any(context in medium for context in contexts):
        return "medium"
    return "low"


def advanced_reflection_audit(scanner: XSSScanner, max_checks: int = 100) -> list[dict[str, Any]]:
    """Probe discovered GET parameters with inert markers and classify reflection contexts.

    POST parameters are intentionally excluded to avoid creating state or content.
    Findings are reflection observations only; they do not attempt JavaScript execution.
    """
    candidates: list[tuple[str, str]] = []
    for url, groups in sorted(scanner.found_params.items()):
        for param in sorted(groups.get("get", set())):
            if param and (url, str(param)) not in candidates:
                candidates.append((url, str(param)))
    candidates = candidates[:max_checks]
    results: list[dict[str, Any]] = []
    add_log(f"[+] Advanced reflection audit · {len(candidates)} inert GET-parameter checks (cap {max_checks})")
    for index, (url, param) in enumerate(candidates, start=1):
        raise_if_cancelled(scanner)
        marker = f"SNXREFLECT{int(time.time() * 1000) % 1000000:06d}{index:03d}"
        record: dict[str, Any] = {
            "url": url, "parameter": param, "method": "GET", "marker": marker,
            "status": "unknown", "contexts": [], "review_priority": "info",
            "http_status": None, "content_type": "", "occurrences": 0,
        }
        try:
            response = scanner.session.get(
                url, params={param: marker}, timeout=scanner.timeout,
                verify=False, allow_redirects=True,
            )
            body = response.text[:1_500_000]
            contexts = classify_reflection_contexts(body, marker, response.headers.get("Content-Type", ""))
            lower_body = body.casefold()
            exact_count = body.count(marker)
            record.update({
                "http_status": response.status_code,
                "content_type": response.headers.get("Content-Type", "")[:120],
                "final_url": response.url,
                "contexts": contexts,
                "occurrences": exact_count or lower_body.count(marker.casefold()),
                "review_priority": _review_priority(contexts) if contexts else "info",
                "status": "reflected" if contexts else "not_reflected_or_filtered",
            })
        except requests.RequestException as exc:
            record["status"] = "request_error"
            record["error"] = str(exc)[:180]
        results.append(record)
        with _LOCK:
            _STATE["reflection_audit"] = list(results)
        add_log(f"[+] Reflection audit · GET {param}: {record['status']}" +
                (f" · {', '.join(record['contexts'])}" if record["contexts"] else ""))
    total = sum(len(group.get("get", set())) for group in scanner.found_params.values())
    skipped = max(0, total - len(candidates))
    if skipped:
        add_log(f"[!] Reflection audit capped · {skipped} additional GET parameter(s) not probed")
    add_log("[!] Reflection audit reports context only; validate exploitability and output encoding manually")
    return results


_SQL_SENSITIVE_PARAM_RE = re.compile(r"(?:csrf|xsrf|session|auth|password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|signature)", re.I)
_SQL_STATEFUL_PATH_RE = re.compile(r"(?:logout|signout|delete|remove|update|create|purchase|checkout|payment|transfer|subscribe|unsubscribe|reset[-_/]?password|confirm|verify[-_/]?email)", re.I)

_SQL_ERROR_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("MySQL/MariaDB", re.compile(r"\b(?:SQL syntax.*MySQL|mysql_fetch_|mysqli?_\w+|MariaDB server version)\b", re.I)),
    ("PostgreSQL", re.compile(r"\b(?:PostgreSQL.*ERROR|pg_query\(\)|PG::SyntaxError|unterminated quoted string)\b", re.I)),
    ("Microsoft SQL Server", re.compile(r"\b(?:SQL Server.*(?:syntax|error)|Unclosed quotation mark|ODBC SQL Server Driver|Microsoft OLE DB Provider for SQL Server)\b", re.I)),
    ("Oracle", re.compile(r"\b(?:ORA-\d{5}|Oracle.*(?:error|exception))\b", re.I)),
    ("SQLite", re.compile(r"\b(?:SQLite/JDBCDriver|SQLite\.Exception|sqlite3?\.OperationalError|near .{1,30}: syntax error)\b", re.I)),
    ("Generic SQL/ODBC", re.compile(r"(?:SQLSTATE\[[0-9A-Z]+\]|ODBC SQL|PDOException.*SQL|syntax error at or near)", re.I)),
)


def _set_query_parameter(url: str, parameter: str, value: str) -> str:
    """Return URL with exactly one replaced parameter, preserving other query items."""
    parts = urlsplit(url)
    pairs = [(key, existing) for key, existing in parse_qsl(parts.query, keep_blank_values=True)
             if key != parameter]
    pairs.append((parameter, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs, doseq=True), parts.fragment))


def _sql_error_vendor(body: str) -> str | None:
    sample = (body or "")[:1_500_000]
    for vendor, pattern in _SQL_ERROR_SIGNATURES:
        if pattern.search(sample):
            return vendor
    return None


def _normalized_response_text(response: requests.Response, probe_value: str = "") -> str:
    """Bounded response representation used only for paired-difference hints."""
    text = re.sub(r"\s+", " ", (response.text or "")[:80_000]).strip()
    # Replace reflected input values so an application echo does not masquerade
    # as a boolean-result difference. The response itself is never persisted.
    if probe_value:
        variants = {probe_value, quote(probe_value, safe=""), quote_plus(probe_value, safe=""), unquote(probe_value)}
        for variant in variants:
            if variant:
                text = re.sub(re.escape(variant), "SQL_PROBE_VALUE", text, flags=re.I)
    return text


def _sql_request_template(scanner: XSSScanner, endpoint: str, parameter: str) -> str:
    """Choose a real, in-memory query template for an endpoint/GET parameter."""
    templates: list[str] = []
    if urlsplit(str(endpoint)).query:
        templates.append(str(endpoint))
    stored = getattr(scanner, "get_query_templates", {}) or {}
    templates.extend(str(item) for item in stored.get(endpoint, []) if item)

    # Prefer a template carrying the parameter itself so its original value
    # can guide context selection; otherwise retain sibling query arguments.
    for template in templates:
        if any(key == parameter for key, _ in parse_qsl(urlsplit(template).query, keep_blank_values=True)):
            return template
    return templates[0] if templates else str(endpoint)


def advanced_sql_injection_audit(scanner: XSSScanner, max_parameters: int = 20) -> list[dict[str, Any]]:
    """Run low-impact SQLi indicators against discovered GET parameters only.

    Candidate discovery merges crawler GET parameters, actual query-string
    templates, and GET findings. The latter is important because some scanner
    discovery paths can report a reflected GET parameter without adding it to
    ``found_params``. Four paced ordinary GET requests are used per parameter.
    There are no POST, time-delay, stacked-statement, UNION, enumeration, or
    write probes.
    """
    candidates: list[tuple[str, str, str]] = []
    sensitive_skipped = 0
    stateful_skipped = 0
    discovered_get: set[tuple[str, str]] = set()
    seen: set[tuple[str, str, str]] = set()

    def add_candidate(endpoint_value: str, parameter_value: str) -> None:
        nonlocal sensitive_skipped, stateful_skipped
        endpoint = str(endpoint_value or "").strip()
        parameter = str(parameter_value or "").strip()
        if not endpoint or not parameter:
            return
        parts = urlsplit(endpoint)
        base_endpoint = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        discovered_get.add((base_endpoint, parameter))
        if _SQL_STATEFUL_PATH_RE.search(parts.path):
            stateful_skipped += 1
            return
        if _SQL_SENSITIVE_PARAM_RE.search(parameter):
            sensitive_skipped += 1
            return
        template = _sql_request_template(scanner, base_endpoint, parameter)
        # Prefer the actual endpoint URL when it carries the parameter; the
        # template helper preserves sibling arguments for crawler base keys.
        if parts.query and any(k == parameter for k, _ in parse_qsl(parts.query, keep_blank_values=True)):
            template = endpoint
        key = (base_endpoint, parameter, template)
        if key not in seen:
            seen.add(key)
            candidates.append(key)

    for url, groups in sorted((getattr(scanner, "found_params", {}) or {}).items()):
        for param in sorted(groups.get("get", set())):
            add_candidate(str(url), str(param))

    # Some discovery routines keep templates even if a later normalizer has
    # omitted a corresponding found_params entry. Recover those GET names.
    explicit_gets = {
        urlunsplit((urlsplit(str(endpoint)).scheme, urlsplit(str(endpoint)).netloc,
                    urlsplit(str(endpoint)).path, "", "")): set(groups.get("get", set()))
        for endpoint, groups in (getattr(scanner, "found_params", {}) or {}).items()
    }
    for endpoint, templates in (getattr(scanner, "get_query_templates", {}) or {}).items():
        parsed_endpoint = urlsplit(str(endpoint))
        base_endpoint = urlunsplit((parsed_endpoint.scheme, parsed_endpoint.netloc, parsed_endpoint.path, "", ""))
        # Use query templates as a discovery fallback only if this endpoint has
        # no parameter map. Do not turn sibling arguments into extra tests when
        # a narrower explicit set is already available.
        if explicit_gets.get(base_endpoint):
            continue
        for template in templates or []:
            for param, _value in parse_qsl(urlsplit(str(template)).query, keep_blank_values=True):
                add_candidate(str(template), str(param))

    # A confirmed GET XSS/reflection observation is also direct evidence that
    # the parameter exists; use it as a fallback candidate, not as SQL proof.
    for finding in (getattr(scanner, "vulnerabilities", []) or []):
        if str(finding.get("method", "")).upper() == "GET" and finding.get("param"):
            add_candidate(str(finding.get("url") or getattr(scanner, "target", "")), str(finding["param"]))

    # A target supplied with a query string is a valid seed even if the crawl
    # was interrupted before the crawler persisted its normal parameter map.
    target = str(getattr(scanner, "target", "") or "")
    for param, _value in parse_qsl(urlsplit(target).query, keep_blank_values=True):
        add_candidate(target, param)

    total_candidates = len(candidates)
    discovered_count = len(discovered_get)
    candidates = candidates[:max(0, int(max_parameters))]
    results: list[dict[str, Any]] = []
    meta = {
        "enabled": True,
        "discovered_get_parameters": discovered_count,
        "eligible_parameters": total_candidates,
        "selected_parameters": len(candidates),
        "skipped_sensitive": sensitive_skipped,
        "skipped_stateful": stateful_skipped,
        "capped": max(0, total_candidates - len(candidates)),
        "requests_sent": 0,
    }
    with _LOCK:
        _STATE["sql_audit_meta"] = dict(meta)
        _STATE["sql_audit_status"] = "running" if candidates else "no_parameters"
    add_log(f"[+] SQL injection diagnostics · {len(candidates)} eligible GET parameter(s) selected from {discovered_count} discovered")
    if not candidates:
        if discovered_count:
            add_log("[!] SQL diagnostics found GET parameters, but all were excluded by sensitive-name or state-changing-route safeguards")
        else:
            add_log("[!] SQL diagnostics did not run: no GET parameters were discovered. Use a query URL such as /items?id=42 or enable common-parameter discovery on an authorized staging target.")

    for index, (url, param, request_template) in enumerate(candidates, start=1):
        raise_if_cancelled(scanner)
        marker = f"SNQL{int(time.time() * 1000) % 1000000:06d}{index:03d}"
        existing_values = [value for key, value in parse_qsl(urlsplit(request_template).query, keep_blank_values=True) if key == param]
        observed_value = existing_values[-1] if existing_values else ""
        numeric_context = bool(observed_value.strip().isdigit())
        preserved_siblings = any(key != param for key, _ in parse_qsl(urlsplit(request_template).query, keep_blank_values=True))

        if numeric_context:
            baseline_value = observed_value.strip()[:24]
            probes = [
                ("baseline", baseline_value),
                ("quote", baseline_value + "'"),
                ("boolean_true", baseline_value + " AND 1=1"),
                ("boolean_false", baseline_value + " AND 1=2"),
            ]
        else:
            safe_observed = bool(re.fullmatch(r"[A-Za-z0-9._ -]{1,64}", observed_value or ""))
            baseline_value = observed_value if safe_observed else f"{marker}BASE"
            probes = [
                ("baseline", baseline_value),
                ("quote", baseline_value + "'"),
                ("boolean_true", baseline_value + "' AND '1'='1"),
                ("boolean_false", baseline_value + "' AND '1'='2"),
            ]

        record_context = "numeric" if numeric_context else "string_or_unknown"
        record: dict[str, Any] = {
            "url": url, "parameter": param, "method": "GET", "status": "no_signal",
            "signals": [], "review_priority": "info", "confidence": "not_assessed",
            "probe_requests": 0, "http_statuses": {}, "response_sizes": {},
            "boolean_similarity": None, "boolean_size_delta": None,
            "true_vs_baseline_similarity": None, "false_vs_baseline_similarity": None,
            "database_error_vendor": None, "parameter_context_hint": record_context,
            "query_context_preserved": preserved_siblings,
        }
        responses: dict[str, requests.Response] = {}
        request_failed = False
        for probe_name, value in probes:
            raise_if_cancelled(scanner)
            try:
                probe_url = _set_query_parameter(request_template, param, value)
                record["probe_requests"] += 1
                meta["requests_sent"] += 1
                with _LOCK:
                    _STATE["sql_audit_meta"] = dict(meta)
                response = scanner.session.get(probe_url, timeout=scanner.timeout,
                                               verify=False, allow_redirects=False)
                responses[probe_name] = response
                record["http_statuses"][probe_name] = response.status_code
                record["response_sizes"][probe_name] = len(response.content or b"")
                vendor = _sql_error_vendor(response.text)
                if vendor and not record["database_error_vendor"]:
                    record["database_error_vendor"] = vendor
            except requests.RequestException as exc:
                record["status"] = "request_error"
                record["error"] = str(exc)[:180]
                request_failed = True
                break

        if record["database_error_vendor"]:
            record["signals"].append("database_error_signature")
        if not request_failed and all(name in responses for name in ("baseline", "boolean_true", "boolean_false")):
            probe_values = dict(probes)
            normalized = {
                name: _normalized_response_text(response, probe_values[name])
                for name, response in responses.items()
            }
            baseline_text = normalized["baseline"]
            true_text = normalized["boolean_true"]
            false_text = normalized["boolean_false"]
            similarity = SequenceMatcher(None, true_text, false_text).ratio() if (true_text or false_text) else 1.0
            size_delta = abs(len(true_text) - len(false_text)) / max(len(true_text), len(false_text), 1)
            true_base = SequenceMatcher(None, baseline_text, true_text).ratio() if (baseline_text or true_text) else 1.0
            false_base = SequenceMatcher(None, baseline_text, false_text).ratio() if (baseline_text or false_text) else 1.0
            record["boolean_similarity"] = round(similarity, 4)
            record["boolean_size_delta"] = round(size_delta, 4)
            record["true_vs_baseline_similarity"] = round(true_base, 4)
            record["false_vs_baseline_similarity"] = round(false_base, 4)
            paired_diff = (responses["boolean_true"].status_code != responses["boolean_false"].status_code or
                           (size_delta >= 0.12 and similarity <= 0.95))
            if paired_diff:
                record["signals"].append("boolean_response_differential")

        if record["database_error_vendor"]:
            record.update({"status": "database_error_indicator", "review_priority": "high",
                           "confidence": "manual_validation_required"})
        elif "boolean_response_differential" in record["signals"]:
            record.update({"status": "possible_boolean_differential", "review_priority": "medium",
                           "confidence": "low_heuristic"})
        elif request_failed:
            record.setdefault("confidence", "not_assessed")
        else:
            record.update({"status": "no_obvious_signal", "review_priority": "info",
                           "confidence": "heuristic_only"})
        results.append(record)
        with _LOCK:
            _STATE["sql_audit"] = list(results)
            _STATE["sql_audit_meta"] = dict(meta)
        add_log(f"[+] SQL diagnostics · GET {param}: {record['status']} · {record['probe_requests']} request(s)" +
                (f" · {', '.join(record['signals'])}" if record["signals"] else ""))

    if meta["capped"]:
        add_log(f"[!] SQL diagnostics capped · {meta['capped']} additional GET parameter(s) not tested")
    if sensitive_skipped or stateful_skipped:
        add_log(f"[+] SQL diagnostics skipped {sensitive_skipped} sensitive parameter(s) and {stateful_skipped} potentially state-changing endpoint parameter(s)")
    with _LOCK:
        _STATE["sql_audit_meta"] = dict(meta)
        _STATE["sql_audit_status"] = "complete" if candidates else "no_parameters"
    add_log(f"[+] SQL diagnostics finished · {len(results)} parameter check(s), {meta['requests_sent']} request(s)")
    add_log("[!] SQL diagnostics are low-impact heuristics, not proof; confirm manually in an approved staging environment")
    return results


def sql_audit_worker(scanner: XSSScanner) -> None:
    """Run SQL diagnostics against the most recently completed in-memory scan."""
    try:
        pacing = getattr(scanner, "_request_pacing_config", None)
        if isinstance(pacing, dict):
            pacing["delay_seconds"] = max(0.15, float(pacing.get("delay_seconds", 0.0)))
        results = advanced_sql_injection_audit(scanner, max_parameters=20)
        with _LOCK:
            summary = dict(_STATE.get("summary") or {})
            summary.update({
                "sql_checks_run": len(results),
                "sql_signals": sum(bool(item.get("signals")) for item in results),
                "sql_probe_requests": (_STATE.get("sql_audit_meta") or {}).get("requests_sent", 0),
                "requests_sent": getattr(scanner, "request_count", summary.get("requests_sent", 0)),
            })
            _STATE["summary"] = summary
    except ScanCancelled:
        with _LOCK:
            _STATE["sql_audit_status"] = "cancelled"
        add_log("[!] SQL diagnostics cancelled")
    except Exception as exc:
        with _LOCK:
            _STATE["sql_audit_status"] = "error"
        add_log(f"[!] SQL diagnostics failed: {type(exc).__name__}: {str(exc)[:160]}")


def audit_security_headers(headers: Any, scheme: str = "https") -> list[dict[str, Any]]:
    """Review common browser security headers without treating absence as XSS."""
    values = {str(k).lower(): str(v).strip() for k, v in (headers or {}).items()}
    csp = values.get("content-security-policy", "")
    frame_protected = "frame-ancestors" in csp.lower() or bool(values.get("x-frame-options"))
    checks = [
        ("Strict-Transport-Security", scheme == "https" and "strict-transport-security" in values,
         "Add HSTS on HTTPS responses after confirming all subdomains support HTTPS.", "high"),
        ("Content-Security-Policy", bool(csp),
         "Define a restrictive Content-Security-Policy; avoid unsafe-inline where practical.", "high"),
        ("Frame protection", frame_protected,
         "Set CSP frame-ancestors or X-Frame-Options to reduce clickjacking exposure.", "medium"),
        ("X-Content-Type-Options", values.get("x-content-type-options", "").lower() == "nosniff",
         "Set X-Content-Type-Options: nosniff.", "medium"),
        ("Referrer-Policy", "referrer-policy" in values,
         "Set a deliberate Referrer-Policy such as strict-origin-when-cross-origin.", "low"),
        ("Permissions-Policy", "permissions-policy" in values,
         "Restrict browser features that the application does not use.", "low"),
    ]
    return [{"name": name, "present": bool(present), "value": (csp if name == "Content-Security-Policy" else values.get({"Strict-Transport-Security":"strict-transport-security", "X-Content-Type-Options":"x-content-type-options", "Referrer-Policy":"referrer-policy", "Permissions-Policy":"permissions-policy", "Frame protection":"x-frame-options"}.get(name, ""), "") or ("CSP frame-ancestors" if name == "Frame protection" and "frame-ancestors" in csp.lower() else "")), "recommendation": recommendation, "severity": severity} for name, present, recommendation, severity in checks]


def audit_cookie_flags(response: requests.Response, scheme: str = "https") -> list[dict[str, Any]]:
    """Summarize cookie security attributes without exposing cookie values."""
    raw_headers: list[str] = []
    try:
        header_store = response.raw.headers
        if hasattr(header_store, "getlist"):
            raw_headers = list(header_store.getlist("Set-Cookie"))
    except Exception:
        raw_headers = []
    if not raw_headers:
        combined = response.headers.get("Set-Cookie", "")
        if combined:
            raw_headers = [combined]

    audited: list[dict[str, Any]] = []
    for raw in raw_headers[:40]:
        parts = [part.strip() for part in str(raw).split(";") if part.strip()]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()[:100] or "unnamed cookie"
        attrs: dict[str, str] = {}
        for part in parts[1:]:
            key, sep, value = part.partition("=")
            attrs[key.strip().lower()] = value.strip() if sep else ""
        secure = "secure" in attrs
        httponly = "httponly" in attrs
        same_site = attrs.get("samesite", "")
        issues = []
        if scheme.lower() == "https" and not secure:
            issues.append("Secure flag missing")
        if not httponly:
            issues.append("HttpOnly flag missing")
        if not same_site:
            issues.append("SameSite attribute missing")
        elif same_site.lower() == "none" and not secure:
            issues.append("SameSite=None requires Secure")
        audited.append({
            "name": name, "secure": secure, "httponly": httponly,
            "samesite": same_site or "Not set", "issues": issues,
        })
    return audited


def publish_live_snapshot(scanner: XSSScanner) -> None:
    """Publish a best-effort snapshot while crawling/testing is still running."""
    try:
        raw_findings = list(getattr(scanner, "vulnerabilities", []) or [])
        findings = group_findings(raw_findings)
        pages = len(getattr(scanner, "visited", []) or [])
        endpoint_count = len(getattr(scanner, "found_params", {}) or {})
        params_count = 0
        for buckets in list((getattr(scanner, "found_params", {}) or {}).values()):
            params_count += len(buckets.get("get", set())) + len(buckets.get("post", set()))
        endpoints = build_endpoint_inventory(scanner)
    except (RuntimeError, AttributeError, TypeError):
        return
    with _LOCK:
        if _STATE.get("status") not in ("running", "stopping"):
            return
        _STATE["findings"] = findings
        _STATE["endpoints"] = endpoints
        summary = dict(_STATE.get("summary") or {})
        summary.update({
            "target": _STATE.get("target", ""), "status": "Running",
            "pages_crawled": pages, "endpoints_found": endpoint_count,
            "parameters_found": params_count, "findings": len(findings),
        })
        _STATE["summary"] = summary


def live_snapshot_loop(scanner: XSSScanner, stop_event: threading.Event) -> None:
    while not stop_event.wait(0.65):
        publish_live_snapshot(scanner)


def build_endpoint_inventory(scanner: XSSScanner) -> list[dict[str, Any]]:
    """Build a compact, display-safe inventory from URLs visited by the crawler."""
    rows: list[dict[str, Any]] = []
    for url in list(scanner.visited)[:500]:
        params = scanner.found_params.get(url, {}) if isinstance(scanner.found_params, dict) else {}
        get_params = sorted(str(x) for x in (params.get("get", set()) or set()))
        post_params = sorted(str(x) for x in (params.get("post", set()) or set()))
        parsed = urlparse(str(url))
        methods = [m for m, vals in (("GET", get_params), ("POST", post_params)) if vals]
        rows.append({"url": str(url), "path": parsed.path or "/", "methods": methods or ["GET"],
                     "parameter_count": len(set(get_params + post_params)),
                     "parameters": sorted(set(get_params + post_params))})
    return rows


def validate_headers(raw: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in raw.splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            raise ValueError(f"Invalid header line: {line[:80]}")
        name, value = line.split(":", 1)
        name, value = name.strip(), value.strip()
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}", name):
            raise ValueError(f"Invalid header name: {name[:80]}")
        if "\r" in value or "\n" in value or len(value) > 2000:
            raise ValueError(f"Invalid value for header: {name}")
        headers[name] = value
    return headers


def validate_target(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        raise ValueError("Enter a target URL.")
    if "://" not in value:
        if value.startswith("//"):
            value = "https:" + value
        else:
            authority = value.split("/", 1)[0]
            # Permit host:port, but do not reinterpret another URI scheme
            # (for example javascript:, file:, or data:) as an HTTPS hostname.
            if ":" in authority and not re.fullmatch(r"[A-Za-z0-9.-]+:\d{1,5}", authority):
                raise ValueError("Only HTTP and HTTPS targets are supported.")
            value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Target must be a valid HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise ValueError("Do not put credentials in the target URL. Use request headers instead.")
    if any(char.isspace() for char in value):
        raise ValueError("Target URL cannot contain spaces.")
    return value


def scan_worker(config: dict[str, Any], cancel_event: threading.Event) -> None:
    global _LAST_SCANNER
    target = config["target"]
    live_stop = threading.Event()
    live_thread: threading.Thread | None = None
    scanner: XSSScanner | None = None
    try:
        scanner = XSSScanner(
            target=target, max_depth=config["depth"], timeout=config["timeout"],
            threads=5, verbose=False, custom_payloads=None,
            first_only=not config["all_payloads"],
            # Deliberately keep executable WAF-evasion mode disabled. The
            # dashboard provides separate inert WAF normalization diagnostics.
            waf_bypass=False, param_discovery=True, brute_params=True,
            force_test=config["force_params"], deep_scan=config["deep_scan"],
            wayback_limit=40 if config["deep_scan"] else 20,
        )
        install_scan_hooks(scanner, cancel_event, config.get("request_delay_ms", 0))
        scanner.session.headers.update(config["headers"])
        scanner.dom_sinks_found = []
        live_thread = threading.Thread(target=live_snapshot_loop, args=(scanner, live_stop), daemon=True)
        live_thread.start()
        # The engine's legacy DOM helper creates executable PoC variants. The
        # dashboard already performs a passive source/sink review, so suppress
        # that legacy active PoC generator in this UI workflow.
        scanner._test_dom_xss = lambda _url, _soup: []
        writer = StreamWriter()
        add_log(f"[*] Starting authorized assessment of {target}")
        add_log("[*] Phase 1/7 · Passive WAF signature check")
        with redirect_stdout(writer):
            raise_if_cancelled(scanner, cancel_event)
            # Passive signature-based WAF detection, avoiding the engine's
            # active malicious WAF-trigger probes.
            try:
                response = scanner.session.get(target, timeout=scanner.timeout, verify=False, allow_redirects=True)
                response_scheme = urlparse(response.url).scheme
                header_audit = audit_security_headers(response.headers, response_scheme)
                cookie_audit = audit_cookie_flags(response, response_scheme)
                with _LOCK:
                    _STATE["security_headers"] = header_audit
                    _STATE["cookie_audit"] = cookie_audit
                    _STATE["http_meta"] = {"status_code": response.status_code, "final_url": response.url,
                                           "content_type": response.headers.get("Content-Type", "—"),
                                           "response_time_ms": round(response.elapsed.total_seconds() * 1000)}
                detected = scanner._analyze_response_for_waf(response)
                if detected:
                    scanner.waf_detected = detected[0]
                    scanner.waf_info["all_detected"] = detected
                    scanner._print_waf_detection_result(detected)
                else:
                    add_log("[+] No WAF signature detected from the initial response")
            except requests.RequestException as exc:
                add_log(f"[!] Initial response check failed: {exc}")

            if config["waf_checks"]:
                raise_if_cancelled(scanner, cancel_event)
                add_log("[*] WAF diagnostics · inert marker and encoding checks")
                safe_waf_normalization_checks(scanner, target)

            raise_if_cancelled(scanner, cancel_event)
            add_log("[*] Phase 2/7 · Crawling and endpoint discovery")
            scanner.crawl()
            raise_if_cancelled(scanner, cancel_event)
            add_log("[*] Phase 3/7 · Advanced inert reflection-context audit")
            advanced_reflection_audit(scanner)
            raise_if_cancelled(scanner, cancel_event)
            add_log("[*] Phase 4/7 · Passive DOM sink review")
            passive_dom_sink_review(scanner)
            raise_if_cancelled(scanner, cancel_event)
            add_log("[*] Phase 5/7 · XSS parameter checks")
            scanner.test_xss()
            raise_if_cancelled(scanner, cancel_event)
            if config.get("sql_checks", False):
                add_log("[*] Phase 6/7 · Low-impact SQL injection diagnostics (GET only)")
                advanced_sql_injection_audit(scanner, max_parameters=20)
            else:
                add_log("[*] SQL injection diagnostics skipped (not enabled)")
            raise_if_cancelled(scanner, cancel_event)
            add_log("[*] Phase 7/7 · Preparing report")
            scanner.print_results()
            raise_if_cancelled(scanner, cancel_event)
        writer.flush()

        findings = group_findings(scanner.vulnerabilities)
        total_params = sum(len(p.get("get", set())) + len(p.get("post", set())) for p in scanner.found_params.values())
        waf_checks = list(_STATE.get("waf_checks", []))
        summary = {
            "target": scanner.target, "status": "Complete",
            "pages_crawled": len(scanner.visited), "endpoints_found": len(scanner.found_params),
            "parameters_found": total_params, "findings": len(findings),
            "waf_detected": scanner.waf_detected or "Not detected",
            "waf_checks_run": len(waf_checks), "reflection_checks": len(_STATE.get("reflection_audit", [])),
            "sql_checks_run": len(_STATE.get("sql_audit", [])),
            "sql_signals": sum(bool(item.get("signals")) for item in _STATE.get("sql_audit", [])),
            "sql_probe_requests": (_STATE.get("sql_audit_meta") or {}).get("requests_sent", 0),
            "dom_sinks": len(scanner.dom_sinks_found),
            "security_headers_present": sum(1 for h in _STATE.get("security_headers", []) if h.get("present")),
            "security_headers_total": len(_STATE.get("security_headers", [])),
            "cookies_reviewed": len(_STATE.get("cookie_audit", [])),
            "cookies_with_issues": sum(1 for c in _STATE.get("cookie_audit", []) if c.get("issues")),
            "requests_sent": getattr(scanner, "request_count", 0),
            "response_time_ms": _STATE.get("http_meta", {}).get("response_time_ms"),
            "started_at": _STATE.get("started_at"), "finished_at": now_iso(),
            "duration_seconds": max(0, int((datetime.fromisoformat(now_iso()) - datetime.fromisoformat(_STATE["started_at"])).total_seconds())) if _STATE.get("started_at") else 0,
            "profile": config["profile"],
            "request_delay_ms": config.get("request_delay_ms", 0),
        }
        endpoints = build_endpoint_inventory(scanner)
        live_stop.set()
        if live_thread:
            live_thread.join(timeout=1)
        with _LOCK:
            _LAST_SCANNER = scanner
            _STATE.update({"status": "complete", "phase": "Complete", "progress": 100,
                           "finished_at": summary["finished_at"], "summary": summary,
                           "sql_audit_available": True,
                           "findings": findings, "endpoints": endpoints, "dom_sinks": scanner.dom_sinks_found,
                           "waf_detection": scanner.waf_info, "error": None})
            _HISTORY.insert(0, {"target": target, "profile": config["profile"],
                                "finished_at": summary["finished_at"], "duration_seconds": summary["duration_seconds"],
                                "findings": len(findings), "pages_crawled": len(scanner.visited),
                                "endpoints_found": len(scanner.found_params), "status": "complete"})
            del _HISTORY[12:]
        add_log(f"[+] Assessment complete · {len(findings)} grouped finding(s)")
        if not findings:
            add_log("[!] No XSS findings reported. Automated checks are not proof of absence.")
    except ScanCancelled:
        live_stop.set()
        if live_thread:
            live_thread.join(timeout=1)
        if scanner is not None:
            publish_live_snapshot(scanner)
        finished_at = now_iso()
        findings = group_findings(scanner.vulnerabilities) if scanner is not None else list(_STATE.get("findings", []))
        endpoints = build_endpoint_inventory(scanner) if scanner is not None else list(_STATE.get("endpoints", []))
        pages = len(scanner.visited) if scanner is not None else 0
        endpoint_count = len(scanner.found_params) if scanner is not None else 0
        params_count = (sum(len(p.get("get", set())) + len(p.get("post", set())) for p in scanner.found_params.values()) if scanner is not None else 0)
        started_at = _STATE.get("started_at")
        try:
            duration = max(0, int((datetime.fromisoformat(finished_at) - datetime.fromisoformat(started_at)).total_seconds())) if started_at else 0
        except (TypeError, ValueError):
            duration = 0
        summary = dict(_STATE.get("summary") or {})
        summary.update({
            "target": target, "status": "Stopped", "pages_crawled": pages,
            "endpoints_found": endpoint_count, "parameters_found": params_count,
            "findings": len(findings), "requests_sent": getattr(scanner, "request_count", _STATE.get("requests_sent", 0)),
            "waf_detected": (scanner.waf_detected or "Not detected") if scanner is not None else "Not assessed",
            "waf_checks_run": len(_STATE.get("waf_checks", [])), "reflection_checks": len(_STATE.get("reflection_audit", [])),
            "sql_checks_run": len(_STATE.get("sql_audit", [])),
            "sql_signals": sum(bool(item.get("signals")) for item in _STATE.get("sql_audit", [])),
            "sql_probe_requests": (_STATE.get("sql_audit_meta") or {}).get("requests_sent", 0),
            "started_at": started_at, "finished_at": finished_at,
            "duration_seconds": duration, "profile": config.get("profile", "Standard"),
        })
        with _LOCK:
            _STATE.update({"status": "cancelled", "phase": "Stopped", "finished_at": finished_at,
                           "summary": summary, "findings": findings, "endpoints": endpoints,
                           "dom_sinks": list(getattr(scanner, "dom_sinks_found", []) or []) if scanner is not None else list(_STATE.get("dom_sinks", [])),
                           "waf_detection": getattr(scanner, "waf_info", {}) if scanner is not None else _STATE.get("waf_detection", []),
                           "sql_audit_status": "cancelled" if _STATE.get("sql_audit_status") in ("pending", "running") else _STATE.get("sql_audit_status", "disabled"),
                           "error": None})
            _HISTORY.insert(0, {"target": target, "profile": config.get("profile", "Standard"),
                                "finished_at": finished_at, "duration_seconds": duration,
                                "findings": len(findings), "pages_crawled": pages,
                                "endpoints_found": endpoint_count, "status": "cancelled"})
            del _HISTORY[12:]
        add_log(f"[-] Assessment stopped by user · retained {len(findings)} finding(s) and {pages} page(s) of partial results")
    except Exception as exc:
        live_stop.set()
        if live_thread:
            live_thread.join(timeout=1)
        if scanner is not None:
            publish_live_snapshot(scanner)
        with _LOCK:
            _STATE.update({"status": "error", "phase": "Error", "progress": 100,
                           "finished_at": now_iso(), "error": str(exc)[:800],
                           "sql_audit_status": "error" if _STATE.get("sql_audit_status") in ("pending", "running") else _STATE.get("sql_audit_status", "disabled")})
            _HISTORY.insert(0, {"target": target, "profile": config.get("profile", "Standard"),
                                "finished_at": _STATE["finished_at"], "duration_seconds": 0,
                                "findings": 0, "pages_crawled": 0, "endpoints_found": 0, "status": "error"})
            del _HISTORY[12:]
        add_log(f"[!] Scan failed: {exc}")


class Handler(BaseHTTPRequestHandler):
    server_version = "Sentinel-Assessment-UI/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep server request logs out of the console; UI has its own activity feed.
        return

    def _send(self, body: bytes, content_type: str, status: int = 200, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, value: Any, status: int = 200) -> None:
        self._send(json.dumps(value, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 65536:
            raise ValueError("Request body is missing or too large.")
        data = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Invalid request body.")
        return data

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            file_path = STATIC_DIR / "index.html"
            self._send(file_path.read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/state":
            with _LOCK:
                state = json.loads(json.dumps(_STATE, default=str))
            self._json(state)
        elif self.path == "/api/history":
            with _LOCK:
                history = json.loads(json.dumps(_HISTORY, default=str))
            self._json({"history": history, "retention": "Current server session · last 12 scans"})
        elif self.path == "/api/export.json":
            with _LOCK:
                report = {k: _STATE[k] for k in ("summary", "findings", "endpoints", "dom_sinks", "waf_checks", "reflection_audit", "sql_audit", "sql_audit_status", "sql_audit_meta", "waf_detection", "security_headers", "cookie_audit", "http_meta", "logs")}
            self._send(json.dumps(report, indent=2, ensure_ascii=False).encode(), "application/json; charset=utf-8",
                       extra={"Content-Disposition": 'attachment; filename="xss-assessment-report.json"'})
        elif self.path == "/api/export.csv":
            output = io.StringIO()
            fields = ["severity", "type", "method", "parameter", "url", "context", "evidence", "poc_url", "payloads"]
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            with _LOCK:
                findings = list(_STATE["findings"])
            for item in findings:
                row = dict(item)
                row["payloads"] = " | ".join(row.get("payloads", []))
                writer.writerow({k: row.get(k, "") for k in fields})
            self._send(output.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8",
                       extra={"Content-Disposition": 'attachment; filename="xss-findings.csv"'})
        elif self.path == "/api/export.html":
            with _LOCK:
                report = {k: _STATE[k] for k in ("summary", "findings", "endpoints", "dom_sinks", "waf_checks", "reflection_audit", "sql_audit", "sql_audit_status", "sql_audit_meta", "security_headers", "cookie_audit", "http_meta")}
            html = build_html_report(report)
            self._send(html.encode("utf-8"), "text/html; charset=utf-8",
                       extra={"Content-Disposition": 'attachment; filename="xss-assessment-report.html"'})
        else:
            self._json({"error": "Not found"}, 404)

    def do_POST(self) -> None:
        global _SCAN_THREAD, _SCAN_CANCEL_EVENT, _SQL_AUDIT_THREAD, _LAST_SCANNER
        if self.path == "/api/sql-audit":
            try:
                data = self._read_json()
                if not data.get("authorized"):
                    raise ValueError("Confirm that you own the current target or have written permission to test it.")
                if not data.get("sql_authorized"):
                    raise ValueError("Confirm separate authorization for SQL injection diagnostics.")
                with _LOCK:
                    if _STATE.get("status") != "complete":
                        self._json({"error": "Finish a complete assessment before running SQL diagnostics on its discovered parameters."}, 409)
                        return
                    if _LAST_SCANNER is None or not _STATE.get("sql_audit_available"):
                        self._json({"error": "No in-memory completed scan is available. Start a new assessment first."}, 409)
                        return
                    if _STATE.get("sql_audit_status") == "running":
                        self._json({"error": "SQL diagnostics are already running."}, 409)
                        return
                    _STATE.update({"sql_audit": [], "sql_audit_status": "running",
                                   "sql_audit_meta": {"enabled": True, "discovered_get_parameters": 0,
                                                       "eligible_parameters": 0, "selected_parameters": 0,
                                                       "skipped_sensitive": 0, "skipped_stateful": 0,
                                                       "capped": 0, "requests_sent": 0}})
                    _SQL_AUDIT_THREAD = threading.Thread(target=sql_audit_worker, args=(_LAST_SCANNER,), daemon=True)
                    _SQL_AUDIT_THREAD.start()
                add_log("[*] SQL diagnostics manually started against the latest completed scan; GET-only safe mode")
                self._json({"ok": True, "message": "SQL diagnostics started against the latest completed scan."}, 202)
            except (ValueError, json.JSONDecodeError, TypeError) as exc:
                self._json({"error": str(exc)}, 400)
        elif self.path == "/api/scan":
            try:
                data = self._read_json()
                if not data.get("authorized"):
                    raise ValueError("Confirm that you own the target or have written permission to test it.")
                target = validate_target(data.get("target", ""))
                depth = int(data.get("depth", 2))
                timeout = int(data.get("timeout", 10))
                if not 1 <= depth <= 5:
                    raise ValueError("Depth must be between 1 and 5.")
                if not 3 <= timeout <= 30:
                    raise ValueError("Timeout must be between 3 and 30 seconds.")
                headers = validate_headers(str(data.get("headers", "")))
                sql_checks = bool(data.get("sql_checks", False))
                if sql_checks and not data.get("sql_authorized", False):
                    raise ValueError("Confirm separate authorization for SQL injection diagnostics.")
                request_delay_ms = int(data.get("request_delay_ms", 150))
                if request_delay_ms not in (0, 150, 350, 700):
                    raise ValueError("Request pacing must be 0, 150, 350, or 700 milliseconds.")
                if sql_checks:
                    request_delay_ms = max(request_delay_ms, 150)
                config = {
                    "target": target, "depth": depth, "timeout": timeout,
                    "profile": str(data.get("profile", "Standard"))[:24],
                    "all_payloads": bool(data.get("all_payloads", False)),
                    "deep_scan": bool(data.get("deep_scan", False)),
                    "force_params": bool(data.get("force_params", False)),
                    "waf_checks": bool(data.get("waf_checks", True)), "headers": headers,
                    "sql_checks": sql_checks,
                    "request_delay_ms": request_delay_ms,
                }
                with _LOCK:
                    if _STATE["status"] in ("running", "stopping") or _STATE.get("sql_audit_status") == "running":
                        self._json({"error": "An assessment or SQL diagnostics job is already active."}, 409)
                        return
                    _LAST_SCANNER = None
                    _STATE.update({"status": "running", "phase": "Starting", "progress": 2,
                                   "target": target, "started_at": now_iso(), "finished_at": None,
                                   "summary": {"target": target, "status": "Running", "pages_crawled": 0,
                                               "endpoints_found": 0, "parameters_found": 0, "findings": 0},
                                   "findings": [], "endpoints": [], "dom_sinks": [], "waf_checks": [], "reflection_audit": [], "sql_audit": [],
                                   "sql_audit_status": "pending" if sql_checks else "disabled",
                                   "sql_audit_meta": {"enabled": sql_checks, "discovered_get_parameters": 0,
                                                       "eligible_parameters": 0, "selected_parameters": 0,
                                                       "skipped_sensitive": 0, "skipped_stateful": 0,
                                                       "capped": 0, "requests_sent": 0},
                                   "sql_audit_available": False,
                                   "waf_detection": [], "security_headers": [], "cookie_audit": [],
                                   "http_meta": {}, "logs": [], "error": None, "requests_sent": 0})
                    _SCAN_CANCEL_EVENT = threading.Event()
                _SCAN_THREAD = threading.Thread(target=scan_worker, args=(config, _SCAN_CANCEL_EVENT), daemon=True)
                _SCAN_THREAD.start()
                self._json({"ok": True, "message": "Scan started."}, 202)
            except (ValueError, json.JSONDecodeError, TypeError) as exc:
                self._json({"error": str(exc)}, 400)
        elif self.path == "/api/stop":
            with _LOCK:
                if _STATE.get("status") not in ("running", "stopping") or _SCAN_CANCEL_EVENT is None:
                    self._json({"error": "There is no active assessment to stop."}, 409)
                    return
                _SCAN_CANCEL_EVENT.set()
                _STATE.update({"status": "stopping", "phase": "Stop requested · finishing current request"})
            add_log("[*] Stop requested by user. Waiting for any in-flight HTTP request to settle.")
            self._json({"ok": True, "message": "Stop requested. Partial results will be kept."}, 202)
        elif self.path == "/api/clear":
            with _LOCK:
                _LAST_SCANNER = None
                if _STATE["status"] in ("running", "stopping") or _STATE.get("sql_audit_status") == "running":
                    self._json({"error": "Cannot clear results during an active assessment or SQL diagnostics job."}, 409)
                    return
                _STATE.update({"status": "ready", "phase": "Ready", "progress": 0,
                               "target": "", "started_at": None, "finished_at": None,
                               "summary": {}, "findings": [], "endpoints": [], "dom_sinks": [], "waf_checks": [], "reflection_audit": [], "sql_audit": [], "sql_audit_status": "disabled",
                               "sql_audit_meta": {"enabled": False, "discovered_get_parameters": 0, "eligible_parameters": 0, "selected_parameters": 0, "skipped_sensitive": 0, "skipped_stateful": 0, "capped": 0, "requests_sent": 0},
                               "sql_audit_available": False,
                               "waf_detection": [], "security_headers": [], "cookie_audit": [],
                               "http_meta": {}, "logs": [], "error": None, "requests_sent": 0})
            self._json({"ok": True})
        else:
            self._json({"error": "Not found"}, 404)


def esc(value: Any) -> str:
    return (str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


def build_html_report(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    rows = []
    for f in report.get("findings", []):
        rows.append("<tr>" + "".join(f"<td>{esc(value)}</td>" for value in (
            str(f.get("severity", "")).upper(), f.get("type", ""), f.get("method", ""),
            f.get("parameter", ""), f.get("url", ""), f.get("evidence", ""))) + "</tr>")
    finding_rows = "".join(rows) or '<tr><td colspan="6">No findings reported</td></tr>'
    dom_rows = "".join(f"<li>{esc(d.get('sink', 'sink'))} · {esc(d.get('source', 'source'))} · {esc(d.get('severity', 'info'))}</li>" for d in report.get("dom_sinks", [])) or "<li>None reported</li>"
    header_rows = "".join(f"<li><b>{esc(h.get('name'))}:</b> {('Present' if h.get('present') else 'Missing')} — {esc(h.get('recommendation',''))}</li>" for h in report.get("security_headers", [])) or "<li>Not assessed</li>"
    endpoint_rows = "".join(f"<li>{esc(e.get('url',''))} · {esc(', '.join(e.get('methods', [])))} · {esc(e.get('parameter_count',0))} parameter(s)</li>" for e in report.get("endpoints", [])[:100]) or "<li>None inventoried</li>"
    waf_rows = "".join(f"<li>{esc(w.get('name'))}: {esc(w.get('status'))} · HTTP {esc(w.get('http_status', '—'))}</li>" for w in report.get("waf_checks", [])) or "<li>Not run</li>"
    sql_rows = "".join(f"<li><strong>{esc(item.get('status'))}</strong> · GET {esc(item.get('parameter'))} · {esc(item.get('url'))} · {esc(', '.join(item.get('signals', [])) or 'No indicator observed')} · database: {esc(item.get('database_error_vendor') or 'not identified')} · HTTP: {esc(item.get('http_statuses', {}))} · review: {esc(item.get('review_priority'))}</li>" for item in report.get("sql_audit", [])) or "<li>Not run</li>"
    sql_meta = report.get("sql_audit_meta", {}) or {}
    sql_summary = (f"<p class=muted>Status: {esc(report.get('sql_audit_status', 'not recorded'))} · "
                   f"GET parameters discovered: {esc(sql_meta.get('discovered_get_parameters', 0))} · "
                   f"Eligible: {esc(sql_meta.get('eligible_parameters', 0))} · "
                   f"Requests attempted: {esc(sql_meta.get('requests_sent', 0))}</p>")
    reflection_rows = "".join(f"<li>{esc(r.get('method'))} {esc(r.get('parameter'))} · {esc(', '.join(r.get('contexts', [])) or r.get('status'))} · review {esc(r.get('review_priority'))}</li>" for r in report.get("reflection_audit", [])) or "<li>Not run</li>"
    cookie_rows = "".join(f"<li>{esc(c.get('name'))}: Secure={esc(c.get('secure'))}, HttpOnly={esc(c.get('httponly'))}, SameSite={esc(c.get('samesite'))} · {esc('; '.join(c.get('issues', [])) or 'No baseline flag issues')}</li>" for c in report.get("cookie_audit", [])) or "<li>No Set-Cookie headers observed</li>"
    return f'''<!doctype html><html><head><meta charset="utf-8"><title>Sentinel Web Security Assessment Report</title><style>
    body{{font:14px system-ui,sans-serif;margin:36px;color:#172033}}h1{{margin-bottom:4px}}.muted{{color:#667085}}.grid{{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}}.card{{border:1px solid #dce2ea;border-radius:12px;padding:14px;min-width:125px}}table{{border-collapse:collapse;width:100%;margin-top:12px}}th,td{{border-bottom:1px solid #e5e9ef;text-align:left;padding:10px;vertical-align:top;overflow-wrap:anywhere}}th{{background:#f3f6fa}}h2{{margin-top:28px}}.note{{background:#f8fafc;padding:12px;border-left:3px solid #64748b}}</style></head><body>
    <h1>Sentinel Web Security Assessment</h1><div class="muted">Created by Subhajit · Generated {esc(now_iso())}</div><p><b>Target:</b> {esc(summary.get('target', '—'))}</p>
    <div class="grid">{''.join(f'<div class="card"><div class="muted">{esc(k)}</div><b>{esc(v)}</b></div>' for k,v in [('Status',summary.get('status','—')),('XSS findings',summary.get('findings',0)),('Pages',summary.get('pages_crawled',0)),('Endpoints',summary.get('endpoints_found',0)),('Parameters',summary.get('parameters_found',0)),('HTTP requests',summary.get('requests_sent',0)),('WAF',summary.get('waf_detected','—'))])}</div>
    <h2>Findings</h2><table><thead><tr><th>Severity</th><th>Type</th><th>Method</th><th>Parameter</th><th>URL</th><th>Evidence</th></tr></thead><tbody>{finding_rows}</tbody></table>
    <h2>HTTP security headers</h2><ul>{header_rows}</ul><h2>Cookie flag review</h2><ul>{cookie_rows}</ul><h2>Endpoint inventory</h2><ul>{endpoint_rows}</ul><h2>DOM sink observations</h2><ul>{dom_rows}</ul><h2>Advanced reflection-context audit</h2><ul>{reflection_rows}</ul><h2>WAF normalization diagnostics</h2><ul>{waf_rows}</ul><h2>SQL injection diagnostics (GET only)</h2>{sql_summary}<ul>{sql_rows}</ul>
    <p class="note">Automated results are heuristic. A reflected marker is not proof of JavaScript execution, and no reported finding does not prove the target is free of XSS. SQL diagnostics use low-impact syntax and paired boolean indicators only; they do not enumerate or extract data. Response differences and database error text are leads, not proof. Validate findings manually in an authorized test environment. WAF diagnostics use inert markers and do not establish WAF bypass.</p>
    </body></html>'''


def main() -> None:
    try:
        server = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError:
        # Use an ephemeral loopback port if the default is already occupied.
        server = ThreadingHTTPServer((HOST, 0), Handler)
    server.daemon_threads = True
    actual_port = server.server_address[1]
    url = f"http://{HOST}:{actual_port}"
    print(f"\n  Sentinel 1.0 · Created by Subhajit\n  Open: {url}\n  Local-only server; press Ctrl+C to stop.\n")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nShutting down dashboard...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

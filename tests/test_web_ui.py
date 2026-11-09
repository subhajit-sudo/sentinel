import unittest
from pathlib import Path

import web_ui


class DashboardHelpersTest(unittest.TestCase):
    def test_target_validation_adds_https_and_rejects_other_schemes(self):
        self.assertEqual(web_ui.validate_target("example.test"), "https://example.test")
        with self.assertRaises(ValueError):
            web_ui.validate_target("javascript:alert(1)")
        with self.assertRaises(ValueError):
            web_ui.validate_target("https://user:pass@example.test")

    def test_cancel_hook_stops_requests_before_network_io(self):
        import threading
        from types import SimpleNamespace

        scanner = SimpleNamespace(session=web_ui.requests.Session())
        event = threading.Event()
        web_ui.install_scan_hooks(scanner, event)
        event.set()
        with self.assertRaises(web_ui.ScanCancelled):
            scanner.session.get("http://127.0.0.1:1/should-not-connect", timeout=1)
        self.assertEqual(scanner.request_count, 0)

    def test_scan_worker_cancellation_keeps_partial_results(self):
        import threading
        from datetime import timedelta
        from unittest.mock import patch

        entered_crawl = threading.Event()
        class FakeScanner:
            def __init__(self, target, **kwargs):
                self.target = target
                self.max_depth = kwargs.get("max_depth", 1)
                self.timeout = kwargs.get("timeout", 3)
                self.session = web_ui.requests.Session()
                response = web_ui.requests.Response()
                response.url = target
                response.status_code = 200
                response.headers["Content-Type"] = "text/html"
                response._content = b"<html>test</html>"
                response.elapsed = timedelta(milliseconds=7)
                self.session.request = lambda method, url, **opts: response
                self.visited = set()
                self.found_params = {target: {"get": {"q"}, "post": set()}}
                self.vulnerabilities = [{
                    "url": target, "param": "q", "method": "GET", "type": "reflected",
                    "severity": "medium", "payload": "inert-test-marker",
                }]
                self.dom_sinks_found = []
                self.waf_info = {}
                self.waf_detected = None
            def _analyze_response_for_waf(self, response):
                return []
            def crawl(self):
                self.visited.add(self.target)
                entered_crawl.set()
                self._cancel_event.wait(2)
                self.session.get(self.target, timeout=self.timeout)
            def test_xss(self):
                return None
            def print_results(self):
                return None

        event = threading.Event()
        config = {"target": "http://unit.test/", "depth": 1, "timeout": 3,
                  "headers": {}, "all_payloads": False, "deep_scan": False,
                  "force_params": False, "waf_checks": False, "profile": "Quick"}
        previous_state = dict(web_ui._STATE)
        previous_history = list(web_ui._HISTORY)
        try:
            with web_ui._LOCK:
                web_ui._STATE.update({"status": "running", "target": config["target"],
                                      "started_at": web_ui.now_iso(), "summary": {},
                                      "findings": [], "endpoints": [], "logs": [],
                                      "requests_sent": 0})
                web_ui._HISTORY.clear()
            with patch.object(web_ui, "XSSScanner", FakeScanner):
                worker = threading.Thread(target=web_ui.scan_worker, args=(config, event), daemon=True)
                worker.start()
                self.assertTrue(entered_crawl.wait(2), "scanner did not enter crawl phase")
                event.set()
                worker.join(3)
            self.assertFalse(worker.is_alive(), "cancelled worker did not exit promptly")
            self.assertEqual(web_ui._STATE["status"], "cancelled")
            self.assertEqual(web_ui._STATE["summary"]["status"], "Stopped")
            self.assertEqual(len(web_ui._STATE["findings"]), 1)
            self.assertEqual(web_ui._STATE["summary"]["requests_sent"], 1)
        finally:
            with web_ui._LOCK:
                web_ui._STATE.clear()
                web_ui._STATE.update(previous_state)
                web_ui._HISTORY[:] = previous_history

    def test_request_pacing_spaces_requests_and_counts_them(self):
        import threading
        import time
        from types import SimpleNamespace

        starts = []
        def fake_request(method, url, **kwargs):
            starts.append(time.monotonic())
            response = web_ui.requests.Response()
            response.status_code = 200
            response.url = url
            response._content = b"ok"
            return response

        scanner = SimpleNamespace(session=SimpleNamespace(request=fake_request))
        event = threading.Event()
        web_ui.install_scan_hooks(scanner, event, request_delay_ms=80)
        scanner.session.request("GET", "https://unit.test/one")
        scanner.session.request("GET", "https://unit.test/two")
        self.assertEqual(scanner.request_count, 2)
        self.assertGreaterEqual(starts[1] - starts[0], 0.065)
        self.assertEqual(scanner.request_delay_ms, 80)

    def test_request_pacing_wait_is_interruptible_by_stop(self):
        import threading
        import time
        from types import SimpleNamespace

        def fake_request(method, url, **kwargs):
            response = web_ui.requests.Response()
            response.status_code = 200
            response.url = url
            response._content = b"ok"
            return response

        scanner = SimpleNamespace(session=SimpleNamespace(request=fake_request))
        event = threading.Event()
        web_ui.install_scan_hooks(scanner, event, request_delay_ms=700)
        scanner.session.request("GET", "https://unit.test/one")
        outcome = []
        def second_request():
            try:
                scanner.session.request("GET", "https://unit.test/two")
            except web_ui.ScanCancelled:
                outcome.append("cancelled")
        worker = threading.Thread(target=second_request)
        worker.start()
        time.sleep(0.05)
        started = time.monotonic()
        event.set()
        worker.join(0.3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(outcome, ["cancelled"])
        self.assertLess(time.monotonic() - started, 0.3)
        self.assertEqual(scanner.request_count, 1)

    def test_header_validation(self):
        self.assertEqual(web_ui.validate_headers("X-Env: staging\nAccept: text/html"),
                         {"X-Env": "staging", "Accept": "text/html"})
        with self.assertRaises(ValueError):
            web_ui.validate_headers("Not-A-Header")

    def test_security_header_audit_has_six_controls(self):
        audit = web_ui.audit_security_headers({
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        })
        self.assertEqual(len(audit), 6)
        by_name = {item["name"]: item for item in audit}
        self.assertTrue(by_name["Content-Security-Policy"]["present"])
        self.assertTrue(by_name["Frame protection"]["present"])
        self.assertTrue(by_name["X-Content-Type-Options"]["present"])
        self.assertFalse(by_name["Strict-Transport-Security"]["present"])

    def test_group_findings_merges_duplicate_observations(self):
        rows = web_ui.group_findings([
            {"url": "https://example.test/?q=x", "param": "q", "method": "GET", "type": "reflected", "severity": "medium", "payload": "marker-1"},
            {"url": "https://example.test/?q=x", "param": "q", "method": "GET", "type": "reflected", "severity": "high", "payload": "marker-2"},
        ])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "high")
        self.assertEqual(rows[0]["payloads"], ["marker-1", "marker-2"])


    def test_safe_waf_probe_corpus_is_expanded_and_non_executable(self):
        probes = web_ui.build_safe_waf_probes("XSSPROBE123")
        self.assertEqual(len(probes), 30)
        joined = "\n".join(value.lower() for _, value in probes)
        self.assertIn("%3c", joined)
        self.assertIn("&#60;", joined)
        self.assertNotIn("<script", joined)
        self.assertNotIn("javascript:", joined)
        self.assertNotIn("onerror=", joined)
        self.assertIn("XML escaped marker", [label for label, _ in probes])
        self.assertIn("Unicode fullwidth delimiters", [label for label, _ in probes])

    def test_reflection_context_classifier_handles_html_and_json_contexts(self):
        marker = "SNXREFLECT123"
        cases = [
            ('<p>SNXREFLECT123</p>', "text/html", "html_text"),
            ('<input value="SNXREFLECT123">', "text/html", "html_attribute"),
            ('<a href="SNXREFLECT123">x</a>', "text/html", "url_attribute"),
            ('<button onclick="SNXREFLECT123">x</button>', "text/html", "event_handler_attribute"),
            ('<script>const x="SNXREFLECT123";</script>', "text/html", "javascript"),
            ('<style>.x{content:"SNXREFLECT123"}</style>', "text/html", "css"),
            ('<!-- SNXREFLECT123 -->', "text/html", "html_comment"),
            ('{"q":"SNXREFLECT123"}', "application/json", "json_string"),
        ]
        for body, content_type, expected in cases:
            with self.subTest(expected=expected):
                self.assertIn(expected, web_ui.classify_reflection_contexts(body, marker, content_type))
        self.assertEqual(web_ui.classify_reflection_contexts("<p>nothing</p>", marker), [])

    def test_advanced_reflection_audit_only_sends_inert_get_probes(self):
        from types import SimpleNamespace

        calls = []
        class FakeSession:
            def get(self, url, params, **kwargs):
                calls.append((url, dict(params)))
                marker = next(iter(params.values()))
                response = web_ui.requests.Response()
                response.status_code = 200
                response.url = url
                response.headers["Content-Type"] = "text/html; charset=utf-8"
                response._content = f"<main>{marker}</main>".encode("utf-8")
                return response

        scanner = SimpleNamespace(
            found_params={"https://unit.test/search": {"get": {"q"}, "post": {"comment"}}},
            session=FakeSession(), timeout=2, _cancel_event=None,
        )
        results = web_ui.advanced_reflection_audit(scanner, max_checks=10)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["parameter"], "q")
        self.assertEqual(results[0]["contexts"], ["html_text"])
        self.assertEqual(results[0]["review_priority"], "low")
        self.assertEqual(len(calls), 1)
        self.assertEqual(set(calls[0][1]), {"q"})

    def test_sql_error_signature_recognizes_common_database_errors(self):
        self.assertEqual(web_ui._sql_error_vendor("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"), "MySQL/MariaDB")
        self.assertEqual(web_ui._sql_error_vendor("SQLSTATE[42000]: syntax error"), "Generic SQL/ODBC")
        self.assertIsNone(web_ui._sql_error_vendor("No database error is present"))

    def test_set_query_parameter_replaces_value_and_preserves_other_parameters(self):
        updated = web_ui._set_query_parameter("https://unit.test/items?id=old&lang=en&id=duplicate#top", "id", "1 AND 1=1")
        parsed = web_ui.urlsplit(updated)
        self.assertEqual(parsed.fragment, "top")
        self.assertEqual(web_ui.parse_qsl(parsed.query), [("lang", "en"), ("id", "1 AND 1=1")])

    def test_sql_response_normalizer_masks_reflected_boolean_probe_values(self):
        true_value = "SNQL123BOOL' AND '1'='1"
        false_value = "SNQL123BOOL' AND '1'='2"
        true_response = web_ui.requests.Response()
        false_response = web_ui.requests.Response()
        true_response._content = f"<p>Search was {true_value}</p>".encode()
        false_response._content = f"<p>Search was {false_value}</p>".encode()
        self.assertEqual(
            web_ui._normalized_response_text(true_response, true_value),
            web_ui._normalized_response_text(false_response, false_value),
        )

    def test_sql_audit_uses_only_four_get_probes_and_never_post(self):
        from types import SimpleNamespace

        calls = []
        class FakeSession:
            def get(self, url, **kwargs):
                calls.append(url)
                value = dict(web_ui.parse_qsl(web_ui.urlsplit(url).query)).get("q", "")
                response = web_ui.requests.Response()
                response.status_code = 200
                response.url = url
                response.headers["Content-Type"] = "text/html"
                if "'1'='2" in value:
                    response._content = b"<p>no rows</p>"
                elif "'1'='1" in value:
                    response._content = (b"<p>rows found and a longer result set returned from the search page</p>" * 5)
                else:
                    response._content = b"<p>ordinary response</p>"
                return response

        scanner = SimpleNamespace(
            found_params={"https://unit.test/search?lang=en": {"get": {"q", "access_token"}, "post": {"comment"}}},
            session=FakeSession(), timeout=2, _cancel_event=None,
        )
        results = web_ui.advanced_sql_injection_audit(scanner, max_parameters=10)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(calls), 4)
        self.assertEqual(results[0]["probe_requests"], 4)
        self.assertEqual(results[0]["method"], "GET")
        self.assertIn("boolean_response_differential", results[0]["signals"])
        self.assertTrue(all("comment" not in url for url in calls))

    def test_sql_audit_selects_numeric_probe_pair_for_numeric_url_values(self):
        from types import SimpleNamespace
        seen = []

        class FakeSession:
            def get(self, url, **kwargs):
                value = dict(web_ui.parse_qsl(web_ui.urlsplit(url).query)).get("id", "")
                seen.append(value)
                response = web_ui.requests.Response()
                response.status_code = 200
                response.url = url
                response._content = b"<p>normal result</p>"
                return response

        scanner = SimpleNamespace(
            found_params={"https://unit.test/item?id=42": {"get": {"id"}, "post": set()}},
            session=FakeSession(), timeout=2, _cancel_event=None,
        )
        result = web_ui.advanced_sql_injection_audit(scanner)[0]
        self.assertEqual(result["parameter_context_hint"], "numeric")
        self.assertEqual(seen, ["42", "42'", "42 AND 1=1", "42 AND 1=2"])

    def test_sql_audit_uses_crawler_query_template_and_preserves_sibling_parameters(self):
        from types import SimpleNamespace
        seen = []

        class FakeSession:
            def get(self, url, **kwargs):
                parsed = web_ui.urlsplit(url)
                params = dict(web_ui.parse_qsl(parsed.query, keep_blank_values=True))
                seen.append(params)
                response = web_ui.requests.Response()
                response.status_code = 200
                response.url = url
                response._content = b"<p>normal product result</p>"
                return response

        scanner = SimpleNamespace(
            found_params={"https://unit.test/item": {"get": {"id"}, "post": set()}},
            get_query_templates={"https://unit.test/item": ["https://unit.test/item?id=42&lang=en"]},
            session=FakeSession(), timeout=2, _cancel_event=None,
        )
        result = web_ui.advanced_sql_injection_audit(scanner)[0]
        self.assertEqual(result["parameter_context_hint"], "numeric")
        self.assertTrue(result["query_context_preserved"])
        self.assertEqual(len(seen), 4)
        self.assertTrue(all(row.get("lang") == "en" for row in seen))
        self.assertEqual([row["id"] for row in seen], ["42", "42'", "42 AND 1=1", "42 AND 1=2"])

    def test_scanner_captures_query_templates_before_base_url_normalization(self):
        scanner = web_ui.XSSScanner("https://unit.test", max_depth=1, param_discovery=False,
                                    brute_params=False, force_test=False)
        scanner._extract_url_params("https://unit.test/items?id=42&lang=en")
        base = "https://unit.test/items"
        self.assertEqual(scanner.found_params[base]["get"], {"id", "lang"})
        self.assertEqual(scanner.get_query_templates[base], ["https://unit.test/items?id=42&lang=en"])

    def test_sql_audit_end_to_end_uses_parameters_collected_by_real_crawler(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from urllib.parse import parse_qs, urlsplit

        class Handler(BaseHTTPRequestHandler):
            seen = []
            def do_GET(self):
                parsed = urlsplit(self.path)
                params = parse_qs(parsed.query, keep_blank_values=True)
                self.seen.append(params)
                if params.get("lang") != ["en"]:
                    body = b"<p>missing language context</p>"
                else:
                    current_id = params.get("id", [""])[0]
                    if current_id == "42'":
                        body = b"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
                    elif "AND 1=2" in current_id:
                        body = b"<p>No item found</p>"
                    else:
                        body = b"<p>Item 42 exists and is visible to the authorized test account</p>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *_args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        scanner = None
        try:
            target = f"http://127.0.0.1:{server.server_port}/item?id=42&lang=en"
            scanner = web_ui.XSSScanner(target, max_depth=1, timeout=2, param_discovery=False,
                                        brute_params=False, force_test=False)
            scanner.crawl()
            results = web_ui.advanced_sql_injection_audit(scanner, max_parameters=5)
            result = next(item for item in results if item["parameter"] == "id")
            self.assertEqual(result["parameter_context_hint"], "numeric")
            self.assertEqual(result["status"], "database_error_indicator")
            self.assertTrue(result["query_context_preserved"])
            self.assertEqual(len(Handler.seen), 9)  # one crawl + four probes for each of two GET parameters
            self.assertTrue(all(row.get("lang") == ["en"] for row in Handler.seen[:5]))
            self.assertTrue(all("id" in row for row in Handler.seen))
        finally:
            if scanner is not None:
                scanner.session.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_manual_sql_audit_endpoint_requires_separate_authorization_and_runs(self):
        import copy
        import threading
        from http.server import ThreadingHTTPServer
        from types import SimpleNamespace

        calls = []
        class FakeSession:
            def get(self, url, **kwargs):
                calls.append(url)
                response = web_ui.requests.Response()
                response.status_code = 200
                response.url = url
                response._content = b"<p>stable result</p>"
                return response

        previous_state = copy.deepcopy(web_ui._STATE)
        previous_scanner = web_ui._LAST_SCANNER
        previous_thread = web_ui._SQL_AUDIT_THREAD
        scanner = SimpleNamespace(
            target="http://unit.test/items?q=sample",
            found_params={"http://unit.test/items": {"get": {"q"}, "post": set()}},
            get_query_templates={"http://unit.test/items": ["http://unit.test/items?q=sample"]},
            vulnerabilities=[], session=FakeSession(), timeout=2, _cancel_event=None,
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), web_ui.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        try:
            with web_ui._LOCK:
                web_ui._STATE.update({"status": "complete", "sql_audit_status": "disabled",
                                      "sql_audit_available": True, "sql_audit": [], "summary": {}})
                web_ui._LAST_SCANNER = scanner
            thread.start()
            endpoint = f"http://127.0.0.1:{server.server_port}/api/sql-audit"
            denied = web_ui.requests.post(endpoint, json={"authorized": True, "sql_authorized": False}, timeout=2)
            self.assertEqual(denied.status_code, 400)
            self.assertEqual(calls, [])
            accepted = web_ui.requests.post(endpoint, json={"authorized": True, "sql_authorized": True}, timeout=2)
            self.assertEqual(accepted.status_code, 202)
            self.assertTrue(web_ui._SQL_AUDIT_THREAD)
            web_ui._SQL_AUDIT_THREAD.join(3)
            self.assertFalse(web_ui._SQL_AUDIT_THREAD.is_alive())
            self.assertEqual(len(calls), 4)
            self.assertEqual(web_ui._STATE["sql_audit_status"], "complete")
            self.assertEqual(web_ui._STATE["sql_audit_meta"]["requests_sent"], 4)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            with web_ui._LOCK:
                web_ui._STATE.clear()
                web_ui._STATE.update(previous_state)
                web_ui._LAST_SCANNER = previous_scanner
                web_ui._SQL_AUDIT_THREAD = previous_thread

    def test_sql_audit_falls_back_to_confirmed_get_finding_when_parameter_map_is_missing(self):
        from types import SimpleNamespace

        seen = []
        class FakeSession:
            def get(self, url, **kwargs):
                seen.append(url)
                response = web_ui.requests.Response()
                response.status_code = 200
                response.url = url
                response._content = b"<p>stable page content</p>"
                return response

        scanner = SimpleNamespace(
            target="https://unit.test/",
            found_params={},
            get_query_templates={},
            vulnerabilities=[{"method": "GET", "param": "key", "url": "https://unit.test/students"}],
            session=FakeSession(), timeout=2, _cancel_event=None,
        )
        results = web_ui.advanced_sql_injection_audit(scanner)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["parameter"], "key")
        self.assertEqual(results[0]["probe_requests"], 4)
        self.assertEqual(len(seen), 4)
        self.assertEqual(web_ui._STATE["sql_audit_meta"]["discovered_get_parameters"], 1)
        self.assertEqual(web_ui._STATE["sql_audit_meta"]["requests_sent"], 4)
        self.assertEqual(web_ui._STATE["sql_audit_status"], "complete")

    def test_sql_audit_detects_error_signature_without_recording_response_body(self):
        from types import SimpleNamespace

        class FakeSession:
            def get(self, url, **kwargs):
                response = web_ui.requests.Response()
                response.status_code = 500
                response.url = url
                response.headers["Content-Type"] = "text/html"
                response._content = b"SQLSTATE[42000]: syntax error near input"
                return response

        scanner = SimpleNamespace(
            found_params={"https://unit.test/search": {"get": {"q"}, "post": set()}},
            session=FakeSession(), timeout=2, _cancel_event=None,
        )
        results = web_ui.advanced_sql_injection_audit(scanner)
        self.assertEqual(results[0]["status"], "database_error_indicator")
        self.assertEqual(results[0]["database_error_vendor"], "Generic SQL/ODBC")
        self.assertNotIn("response_body", results[0])
        self.assertEqual(results[0]["probe_requests"], 4)

    def test_review_priority_uses_context_sensitivity(self):
        self.assertEqual(web_ui._review_priority(["event_handler_attribute"]), "high")
        self.assertEqual(web_ui._review_priority(["html_attribute"]), "medium")
        self.assertEqual(web_ui._review_priority(["html_text"]), "low")

    def test_safe_waf_probe_corpus_has_30_inert_representations(self):
        probes = web_ui.build_safe_waf_probes("XSSPROBE123")
        self.assertEqual(len(probes), 30)
        joined = "\n".join(value.lower() for _, value in probes)
        self.assertIn("%3c", joined)
        self.assertIn("&#60", joined)
        self.assertNotIn("<script", joined)
        self.assertNotIn("javascript:", joined)
        self.assertNotIn("onerror=", joined)

    def test_cookie_flag_audit_does_not_expose_cookie_values(self):
        response = web_ui.requests.Response()
        response.url = "https://example.test/"
        response.headers["Set-Cookie"] = "sessionid=secret-value; HttpOnly; SameSite=Lax"
        rows = web_ui.audit_cookie_flags(response, "https")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "sessionid")
        self.assertFalse(rows[0]["secure"])
        self.assertTrue(rows[0]["httponly"])
        self.assertIn("Secure flag missing", rows[0]["issues"])
        self.assertNotIn("secret-value", str(rows))

    def test_live_snapshot_publishes_findings_while_running(self):
        class FakeScanner:
            vulnerabilities = [{
                "url": "https://example.test/?q=x", "param": "q", "method": "GET",
                "type": "reflected", "severity": "high", "payload": "marker",
            }]
            visited = {"https://example.test/"}
            found_params = {"https://example.test/": {"get": {"q"}, "post": set()}}

        previous = dict(web_ui._STATE)
        try:
            web_ui._STATE.update({"status": "running", "target": "https://example.test", "summary": {}, "findings": []})
            web_ui.publish_live_snapshot(FakeScanner())
            self.assertEqual(len(web_ui._STATE["findings"]), 1)
            self.assertEqual(web_ui._STATE["summary"]["findings"], 1)
            self.assertEqual(len(web_ui._STATE["endpoints"]), 1)
        finally:
            web_ui._STATE.clear()
            web_ui._STATE.update(previous)

    def test_html_report_escapes_untrusted_values_and_includes_new_sections(self):
        html = web_ui.build_html_report({
            "summary": {"target": "https://example.test"},
            "findings": [{"url": "<script>alert(1)</script>"}],
            "security_headers": [{"name": "Content-Security-Policy", "present": False, "recommendation": "Add CSP"}],
            "cookie_audit": [{"name": "session", "secure": True, "httponly": True, "samesite": "Lax", "issues": []}],
            "endpoints": [{"url": "https://example.test/path", "methods": ["GET"], "parameter_count": 1}],
            "reflection_audit": [{"method": "GET", "parameter": "q", "contexts": ["html_text"], "review_priority": "low"}],
            "sql_audit": [{"method": "GET", "parameter": "id", "status": "possible_boolean_differential", "signals": ["boolean_response_differential"], "review_priority": "medium", "url": "https://example.test/items"}],
        })
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("HTTP security headers", html)
        self.assertIn("Endpoint inventory", html)
        self.assertIn("Cookie flag review", html)
        self.assertIn("Advanced reflection-context audit", html)
        self.assertIn("SQL injection diagnostics (GET only)", html)
        self.assertIn("boolean_response_differential", html)
        self.assertIn("Created by Subhajit", html)


class DashboardStaticUiRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (Path(__file__).resolve().parents[1] / "static" / "index.html").read_text(encoding="utf-8")

    def test_unchanged_poll_snapshots_skip_panel_rebuilds(self):
        self.assertIn("function renderIfChanged(key,value,render)", self.html)
        for section in ("findings", "severity", "security-headers", "cookie-audit", "waf-checks", "dom-sinks", "endpoints", "activity"):
            self.assertIn(f"renderIfChanged('{section}'", self.html)
        self.assertIn("button.dataset.state!==state", self.html)

    def test_sql_injection_panel_requires_explicit_scope_acknowledgement(self):
        self.assertIn('id="sqlChecks"', self.html)
        self.assertIn('id="sqlAuthorized"', self.html)
        self.assertIn('id="sqlAudit"', self.html)
        self.assertIn("sql_checks:$('sqlChecks').checked", self.html)
        self.assertIn("sql_authorized:$('sqlAuthorized').checked", self.html)
        self.assertIn("renderIfChanged('sql-audit',{rows:s.sql_audit||[],status:s.sql_audit_status", self.html)
        self.assertIn("function renderSqlAudit(s)", self.html)
        self.assertIn('id="sqlSummary"', self.html)
        self.assertIn('id="runSqlAuditBtn"', self.html)
        self.assertIn("fetch('/api/sql-audit'", self.html)
        self.assertIn("meta.requests_sent", self.html)

    def test_reflection_audit_panel_and_creator_credit_are_present(self):
        topbar_start = self.html.index('<header class="topbar">')
        topbar_end = self.html.index('</header>', topbar_start)
        topbar = self.html[topbar_start:topbar_end]
        self.assertIn('<div class="top-credit"><span class="online-dot"></span> Created by Subhajit</div>', topbar)
        self.assertLess(topbar.index("Created by Subhajit"), topbar.index("Assessment cockpit"))
        self.assertIn('id="reflectionAudit"', self.html)
        self.assertIn('function renderReflectionAudit(s)', self.html)
        self.assertIn("renderIfChanged('reflection-audit'", self.html)
        self.assertIn("Created by Subhajit", self.html)

    def test_cookie_and_dom_panels_fill_left_column_gap_and_waf_is_full_width(self):
        self.assertIn('<div class="left-diagnostics-grid">', self.html)
        left_stack_start = self.html.index('<div class="left-stack">')
        left_diag_start = self.html.index('<div class="left-diagnostics-grid">')
        right_stack_start = self.html.index('<div class="right-stack">')
        self.assertLess(left_stack_start, left_diag_start)
        self.assertLess(left_diag_start, right_stack_start)
        self.assertIn('<section class="panel side-panel diagnostics-card waf-panel" id="diagnostics">', self.html)
        self.assertIn('.left-diagnostics-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))', self.html)
        self.assertIn('.waf-row-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))', self.html)
        self.assertIn('.left-diagnostics-grid{grid-template-columns:1fr}', self.html)
        self.assertIn('.waf-row-grid{grid-template-columns:1fr}', self.html)
        self.assertNotIn('class="diagnostics-grid"', self.html)

    def test_stop_control_and_live_request_metric_are_present(self):
        self.assertIn('id="stopBtn"', self.html)
        self.assertIn("fetch('/api/stop'", self.html)
        self.assertIn("s.status==='stopping'", self.html)
        self.assertIn('id="mRequests"', self.html)
        self.assertIn("status==='cancelled'", self.html)

    def test_request_pacing_and_remediation_export_controls_exist(self):
        self.assertIn('id="requestPace"', self.html)
        self.assertIn("request_delay_ms:Number($(\'requestPace\').value)", self.html)
        self.assertIn('id="exportRemediation"', self.html)
        self.assertIn('function exportRemediationPlan()', self.html)
        self.assertIn('sentinel-remediation-plan.md', self.html)

    def test_gsd_core_official_installer_is_offered_by_default_and_can_be_rerun(self):
        root = Path(__file__).resolve().parents[1]
        win = (root / 'run_gui.bat').read_text(encoding='utf-8')
        unix = (root / 'run_gui.sh').read_text(encoding='utf-8')
        win_installer = (root / 'install_gsd_core.bat').read_text(encoding='utf-8')
        unix_installer = (root / 'install_gsd_core.sh').read_text(encoding='utf-8')
        command = 'npx --yes @opengsd/gsd-core@latest'
        self.assertIn('choice /C YN /D Y /T 8', win)
        self.assertIn('default Yes', unix)
        self.assertIn(command, win_installer)
        self.assertIn(command, unix_installer)
        self.assertIn('Node.js 18', win_installer)
        self.assertIn('Node.js 18+', unix_installer)
        self.assertIn('Do not copy `agents/` or `commands/`', (root / 'README.md').read_text(encoding='utf-8'))

    def test_live_data_rows_do_not_restart_entrance_animations_on_poll(self):
        self.assertIn('.results tbody tr,.header-item,.dom-item,.endpoint-item,.history-item,.waf-row{animation:none}', self.html)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import html
import time
from collections import deque
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright


class Scanner:
    def __init__(
        self,
        target_url: str,
        max_depth: int = 2,
        max_pages: int = 60,
        timeout: int = 10,
    ) -> None:
        if not target_url:
            raise ValueError("Target URL cannot be empty.")
        parsed = urlparse(target_url.strip())
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("URL must start with http:// or https://")

        self.target_url = self._normalize_url(target_url)
        self.root_host = urlparse(self.target_url).netloc.lower()
        self.max_depth = max(0, int(max_depth))
        self.max_pages = max(1, int(max_pages))
        self.timeout = max(3, int(timeout))

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (compatible; RealWorldSecurityScanner/1.0; "
                    "+https://localhost/security-scanner)"
                )
            }
        )

        self.discovered_urls: Set[str] = set()
        self.forms_by_url: Dict[str, List[dict]] = {}
        self.findings: List[dict] = []
        self.seen_finding_keys: Set[Tuple[str, str, str]] = set()
        self.scan_errors: List[str] = []

        self._xss_payloads = [
            '\"><svg/onload=alert(1)>',
            "<script>alert(1)</script>",
            "'\"><img src=x onerror=alert(1)>",
        ]
        self._sqli_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "'; WAITFOR DELAY '0:0:2'--",
        ]
        self._sqli_signatures = [
            "sql syntax",
            "mysql",
            "mariadb",
            "syntax error",
            "unclosed quotation mark",
            "odbc",
            "pdoexception",
            "postgresql",
            "sqlite error",
            "ora-",
            "warning: mysql",
            "fatal error",
            "you have an error in your sql syntax",
        ]

    def _normalize_url(self, url: str, base: Optional[str] = None) -> str:
        raw = urljoin(base, url) if base else url
        parsed = urlparse(raw.strip())
        if parsed.scheme not in {"http", "https"}:
            return ""
        clean = parsed._replace(fragment="")
        normalized = urlunparse(clean).rstrip("/")
        return normalized

    def _is_same_domain(self, url: str) -> bool:
        host = urlparse(url).netloc.lower()
        return host == self.root_host

    def _should_skip_link(self, url: str) -> bool:
        if not url:
            return True
        lower = url.lower()
        blocked = ("javascript:", "mailto:", "tel:", "data:", "blob:")
        if lower.startswith(blocked):
            return True
        parsed = urlparse(url)
        path = parsed.path.lower()
        skip_ext = (
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".svg",
            ".webp",
            ".pdf",
            ".zip",
            ".rar",
            ".7z",
            ".tar",
            ".gz",
            ".mp4",
            ".mp3",
            ".woff",
            ".woff2",
            ".ttf",
        )
        return path.endswith(skip_ext)

    def _record_finding(
        self,
        severity: str,
        title: str,
        message: str,
        url: str = "",
        evidence: str = "",
        recommendation: str = "",
    ) -> None:
        key = (severity, title, f"{url}|{message}")
        if key in self.seen_finding_keys:
            return
        self.seen_finding_keys.add(key)
        self.findings.append(
            {
                "type": severity,
                "title": title,
                "message": message,
                "url": url,
                "evidence": evidence,
                "recommendation": recommendation,
            }
        )

    def _safe_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            return self.session.request(
                method=method.upper(),
                url=url,
                timeout=self.timeout,
                allow_redirects=True,
                **kwargs,
            )
        except requests.RequestException as exc:
            self.scan_errors.append(f"{method.upper()} {url}: {exc}")
            return None

    def _extract_links_from_html(self, html_text: str, base_url: str) -> Set[str]:
        links: Set[str] = set()
        soup = BeautifulSoup(html_text, "html.parser")
        for anchor in soup.select("a[href]"):
            href = anchor.get("href", "").strip()
            if not href:
                continue
            normalized = self._normalize_url(href, base_url)
            if not normalized or self._should_skip_link(normalized):
                continue
            if self._is_same_domain(normalized):
                links.add(normalized)
        return links

    def _extract_forms(self, html_text: str, base_url: str) -> List[dict]:
        forms: List[dict] = []
        soup = BeautifulSoup(html_text, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", "").strip()
            method = form.get("method", "get").strip().lower()
            enctype = form.get("enctype", "application/x-www-form-urlencoded")
            target = self._normalize_url(action, base_url) if action else base_url
            if not target:
                continue
            fields = []
            for input_tag in form.find_all(["input", "textarea", "select"]):
                tag = input_tag.name.lower()
                name = input_tag.get("name")
                if not name:
                    continue
                field_type = input_tag.get("type", "text").lower()
                value = input_tag.get("value", "")
                options = []
                if tag == "select":
                    options = [
                        option.get("value", "").strip()
                        for option in input_tag.find_all("option")
                        if option.get("value") is not None
                    ]
                fields.append(
                    {
                        "tag": tag,
                        "name": name,
                        "type": field_type,
                        "value": value,
                        "options": options,
                    }
                )
            forms.append(
                {
                    "action": target,
                    "method": method if method in {"get", "post"} else "get",
                    "enctype": enctype,
                    "fields": fields,
                }
            )
        return forms

    def _merge_forms(self, url: str, new_forms: List[dict]) -> None:
        existing = self.forms_by_url.setdefault(url, [])
        seen = {
            (f["action"], f["method"], tuple(field["name"] for field in f["fields"]))
            for f in existing
        }
        for form in new_forms:
            key = (form["action"], form["method"], tuple(field["name"] for field in form["fields"]))
            if key not in seen:
                existing.append(form)
                seen.add(key)

    def _crawl(self) -> None:
        queue = deque([(self.target_url, 0)])

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()

                while queue and len(self.discovered_urls) < self.max_pages:
                    current_url, depth = queue.popleft()
                    if current_url in self.discovered_urls:
                        continue
                    self.discovered_urls.add(current_url)

                    static_resp = self._safe_request("GET", current_url)
                    static_html = static_resp.text if static_resp and static_resp.text else ""
                    static_links = self._extract_links_from_html(static_html, current_url)
                    static_forms = self._extract_forms(static_html, current_url)
                    self._merge_forms(current_url, static_forms)

                    dynamic_links: Set[str] = set()
                    dynamic_html = ""
                    try:
                        page.goto(
                            current_url,
                            wait_until="networkidle",
                            timeout=self.timeout * 1000,
                        )
                        links = page.eval_on_selector_all(
                            "a[href]",
                            "elements => elements.map(e => e.href)",
                        )
                        dynamic_links = {
                            self._normalize_url(link)
                            for link in links
                            if link and not self._should_skip_link(link)
                        }
                        dynamic_links = {
                            link for link in dynamic_links if link and self._is_same_domain(link)
                        }
                        dynamic_html = page.content()
                    except PlaywrightTimeoutError:
                        self.scan_errors.append(f"Playwright timeout on {current_url}")
                    except Exception as exc:
                        self.scan_errors.append(f"Playwright error on {current_url}: {exc}")

                    if dynamic_html:
                        dynamic_forms = self._extract_forms(dynamic_html, current_url)
                        self._merge_forms(current_url, dynamic_forms)

                    if depth < self.max_depth:
                        next_urls = static_links.union(dynamic_links)
                        for next_url in next_urls:
                            if next_url not in self.discovered_urls:
                                queue.append((next_url, depth + 1))

                context.close()
                browser.close()
        except Exception as exc:
            self.scan_errors.append(f"Playwright unavailable, fallback to static crawl only: {exc}")
            self._crawl_static_only(queue)

        # Add root even if no links were discovered.
        self.discovered_urls.add(self.target_url)

    def _crawl_static_only(self, queue: deque) -> None:
        while queue and len(self.discovered_urls) < self.max_pages:
            current_url, depth = queue.popleft()
            if current_url in self.discovered_urls:
                continue
            self.discovered_urls.add(current_url)

            static_resp = self._safe_request("GET", current_url)
            static_html = static_resp.text if static_resp and static_resp.text else ""
            static_links = self._extract_links_from_html(static_html, current_url)
            static_forms = self._extract_forms(static_html, current_url)
            self._merge_forms(current_url, static_forms)

            if depth < self.max_depth:
                for next_url in static_links:
                    if next_url not in self.discovered_urls:
                        queue.append((next_url, depth + 1))

    def _scan_security_headers(self) -> None:
        response = self._safe_request("GET", self.target_url)
        if not response:
            return
        headers = {k.lower(): v for k, v in response.headers.items()}
        required_headers = {
            "content-security-policy": "Defines allowed script/resource sources.",
            "x-frame-options": "Prevents clickjacking by disallowing framing.",
            "x-content-type-options": "Prevents MIME-type sniffing.",
            "referrer-policy": "Controls sensitive referrer leakage.",
            "permissions-policy": "Limits powerful browser APIs.",
        }
        if self.target_url.startswith("https://"):
            required_headers["strict-transport-security"] = "Forces HTTPS for future visits."

        for header, reason in required_headers.items():
            if header not in headers:
                self._record_finding(
                    severity="Warning",
                    title="Missing Security Header",
                    message=f"{header} is missing.",
                    url=self.target_url,
                    recommendation=f"Add {header}. {reason}",
                )

        set_cookie = response.headers.get("Set-Cookie", "")
        if set_cookie:
            cookie_lower = set_cookie.lower()
            if "httponly" not in cookie_lower:
                self._record_finding(
                    severity="Warning",
                    title="Cookie Missing HttpOnly",
                    message="At least one cookie appears without HttpOnly.",
                    url=self.target_url,
                    recommendation="Set HttpOnly on session/auth cookies.",
                )
            if self.target_url.startswith("https://") and "secure" not in cookie_lower:
                self._record_finding(
                    severity="Warning",
                    title="Cookie Missing Secure",
                    message="At least one cookie appears without Secure on HTTPS.",
                    url=self.target_url,
                    recommendation="Set Secure for cookies sent over HTTPS.",
                )
            if "samesite" not in cookie_lower:
                self._record_finding(
                    severity="Info",
                    title="Cookie Missing SameSite",
                    message="At least one cookie appears without SameSite.",
                    url=self.target_url,
                    recommendation="Set SameSite=Lax/Strict based on application flow.",
                )

    def _test_reflected_xss(self) -> None:
        marker = "xss_probe_6731"
        for url in list(self.discovered_urls):
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            targets = list(params.keys()) if params else ["q"]

            for param in targets[:3]:
                for payload in self._xss_payloads[:2]:
                    probe = f"{marker}{payload}"
                    new_params = {k: v[:] for k, v in params.items()}
                    new_params[param] = [probe]
                    encoded_query = urlencode(new_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=encoded_query))
                    response = self._safe_request("GET", test_url)
                    if not response or "text/html" not in response.headers.get("Content-Type", ""):
                        continue

                    body = response.text
                    escaped_probe = html.escape(probe)
                    if probe in body or (marker in body and escaped_probe not in body):
                        self._record_finding(
                            severity="Critical",
                            title="Possible Reflected XSS",
                            message=f"Payload reflected by parameter '{param}'.",
                            url=url,
                            evidence=f"Probe observed in response for {test_url}",
                            recommendation="Contextually encode output and apply strict input validation.",
                        )
                        break

    def _looks_like_sqli_error(self, text: str) -> bool:
        lowered = text.lower()
        return any(signature in lowered for signature in self._sqli_signatures)

    def _test_sqli_query_params(self) -> None:
        for url in list(self.discovered_urls):
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue

            baseline = self._safe_request("GET", url)
            baseline_text = baseline.text if baseline else ""

            for param in list(params.keys())[:3]:
                for payload in self._sqli_payloads[:2]:
                    new_params = {k: v[:] for k, v in params.items()}
                    new_params[param] = [payload]
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))

                    response = self._safe_request("GET", test_url)
                    if not response:
                        continue
                    text = response.text

                    error_triggered = self._looks_like_sqli_error(text) and not self._looks_like_sqli_error(
                        baseline_text
                    )
                    server_error_spike = (
                        baseline is not None
                        and baseline.status_code < 500
                        and response.status_code >= 500
                    )
                    if error_triggered or server_error_spike:
                        self._record_finding(
                            severity="Critical",
                            title="Possible SQL Injection",
                            message=f"Potential SQLi behavior in query parameter '{param}'.",
                            url=url,
                            evidence=f"Probe URL: {test_url}",
                            recommendation="Use parameterized queries and strict server-side validation.",
                        )
                        break

    def _submit_form(self, form: dict, payload: str) -> Optional[requests.Response]:
        target = form.get("action")
        method = form.get("method", "get")
        fields = form.get("fields", [])
        if not target or not self._is_same_domain(target):
            return None

        data = {}
        for field in fields:
            name = field.get("name")
            if not name:
                continue
            tag = field.get("tag", "input")
            field_type = field.get("type", "text")
            value = field.get("value", "")

            if tag == "select":
                options = field.get("options", [])
                data[name] = options[0] if options else payload
            elif field_type in {"hidden", "submit", "button"}:
                data[name] = value
            elif field_type in {"checkbox", "radio"}:
                data[name] = value or "on"
            else:
                data[name] = payload

        if method == "post":
            return self._safe_request("POST", target, data=data)
        return self._safe_request("GET", target, params=data)

    def _submit_form_with_data(self, form: dict, data: dict) -> Optional[requests.Response]:
        target = form.get("action")
        method = form.get("method", "get")
        if not target or not self._is_same_domain(target):
            return None
        if method == "post":
            return self._safe_request("POST", target, data=data)
        return self._safe_request("GET", target, params=data)

    def _looks_like_login_form(self, form: dict) -> bool:
        fields = form.get("fields", [])
        has_password = False
        has_identity = False
        for field in fields:
            field_type = (field.get("type") or "").lower()
            name = (field.get("name") or "").lower()
            if field_type == "password" or "password" in name or "pass" in name:
                has_password = True
            if (
                "user" in name
                or "email" in name
                or "login" in name
                or "account" in name
                or "name" == name
            ):
                has_identity = True
        return has_password and has_identity

    def _build_login_probe_data(self, form: dict, attempt: int) -> dict:
        fields = form.get("fields", [])
        data = {}
        for field in fields:
            name = field.get("name")
            if not name:
                continue
            name_l = name.lower()
            field_type = (field.get("type") or "text").lower()
            value = field.get("value", "")
            if field_type == "password" or "password" in name_l or "pass" in name_l:
                data[name] = f"WrongPassword!{attempt}!"
            elif (
                "user" in name_l
                or "email" in name_l
                or "login" in name_l
                or "account" in name_l
                or name_l == "name"
            ):
                data[name] = f"scanner_user_{attempt}@invalid.test"
            elif field_type in {"hidden", "submit", "button"}:
                data[name] = value
            elif field_type in {"checkbox", "radio"}:
                data[name] = value or "on"
            else:
                data[name] = f"probe_{attempt}"
        return data

    def _test_auth_bruteforce_controls(self) -> None:
        block_keywords = [
            "too many",
            "rate limit",
            "temporarily locked",
            "account locked",
            "captcha",
            "try again later",
            "blocked",
            "slow down",
        ]
        fail_keywords = [
            "invalid",
            "incorrect",
            "login failed",
            "wrong password",
            "authentication failed",
            "bad credentials",
            "sign in failed",
        ]
        tested_targets = set()

        for page_url, forms in self.forms_by_url.items():
            for form in forms:
                if not self._looks_like_login_form(form):
                    continue
                target = form.get("action", page_url)
                if target in tested_targets:
                    continue
                tested_targets.add(target)

                attempts = []
                protected = False
                for i in range(1, 7):
                    data = self._build_login_probe_data(form, i)
                    begin = time.time()
                    response = self._submit_form_with_data(form, data)
                    elapsed = time.time() - begin
                    if not response:
                        continue
                    text_l = response.text.lower()[:4000]
                    attempts.append((response.status_code, elapsed, text_l))
                    if response.status_code == 429 or any(k in text_l for k in block_keywords):
                        protected = True
                        break

                if len(attempts) < 4 or protected:
                    continue

                statuses = [s for s, _, _ in attempts]
                lats = [l for _, l, _ in attempts]
                failed_signals = sum(
                    1 for _, _, body in attempts if any(keyword in body for keyword in fail_keywords)
                )
                baseline = (lats[0] + lats[1]) / 2 if len(lats) >= 2 else lats[0]
                tail = (lats[-1] + lats[-2]) / 2 if len(lats) >= 2 else lats[-1]
                has_throttle_pattern = tail > (baseline * 2.5)

                if len(set(statuses)) <= 2 and failed_signals >= 3 and not has_throttle_pattern:
                    self._record_finding(
                        severity="Critical",
                        title="Possible Brute-Force / Missing Login Rate-Limit",
                        message=(
                            "Multiple failed login attempts were accepted without lockout, "
                            "429 response, CAPTCHA, or clear throttling."
                        ),
                        url=target,
                        recommendation=(
                            "Implement per-account and per-IP rate limiting, progressive delays, "
                            "temporary lockout, MFA, and centralized auth monitoring."
                        ),
                    )

    def _test_form_xss_and_sqli(self) -> None:
        xss_payload = self._xss_payloads[0]
        sqli_payload = self._sqli_payloads[2]

        for page_url, forms in self.forms_by_url.items():
            for form in forms:
                xss_response = self._submit_form(form, xss_payload)
                if xss_response and xss_payload in xss_response.text:
                    self._record_finding(
                        severity="Critical",
                        title="Possible Form XSS",
                        message=f"Form input reflected unsafely after submission from {page_url}.",
                        url=form.get("action", page_url),
                        recommendation="Encode untrusted data on output and sanitize/validate form input.",
                    )

                sqli_response = self._submit_form(form, sqli_payload)
                if sqli_response and self._looks_like_sqli_error(sqli_response.text):
                    self._record_finding(
                        severity="Critical",
                        title="Possible Form SQL Injection",
                        message=f"SQL error pattern appeared after form submission from {page_url}.",
                        url=form.get("action", page_url),
                        recommendation="Use parameterized queries and validate form data server-side.",
                    )

    def _check_sensitive_paths(self) -> None:
        probe_paths = {
            "/.git/HEAD": "Git metadata should never be web-accessible.",
            "/.env": ".env may expose credentials and keys.",
            "/phpinfo.php": "phpinfo() leaks environment configuration.",
            "/server-status": "Server-status reveals internals to attackers.",
        }
        for path, reason in probe_paths.items():
            url = f"{self.target_url}{path}"
            response = self._safe_request("GET", url)
            if not response:
                continue
            if response.status_code == 200 and len(response.text.strip()) > 0:
                self._record_finding(
                    severity="Warning",
                    title="Potential Sensitive Endpoint Exposed",
                    message=f"{path} returned HTTP 200.",
                    url=url,
                    recommendation=reason,
                )

    def run(self) -> dict:
        start = time.time()
        self.findings = []
        self.seen_finding_keys.clear()
        self.scan_errors = []
        self.discovered_urls = set()
        self.forms_by_url = {}

        self._crawl()
        self._scan_security_headers()
        self._check_sensitive_paths()
        self._test_reflected_xss()
        self._test_sqli_query_params()
        self._test_form_xss_and_sqli()
        self._test_auth_bruteforce_controls()

        duration = round(time.time() - start, 2)
        stats = {
            "scanned_urls": len(self.discovered_urls),
            "detected_forms": sum(len(v) for v in self.forms_by_url.values()),
            "duration_seconds": duration,
            "max_depth": self.max_depth,
            "max_pages": self.max_pages,
        }
        return {
            "findings": self.findings,
            "stats": stats,
            "errors": self.scan_errors[:15],
        }

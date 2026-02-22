
import requests
import urllib.parse
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

class Scanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip("/")
        self.target_links = []
        self.vulnerabilities = []
        self.session = requests.Session()

        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(headless=True)
        self.page = self.browser.new_page()

    # ---------------- Crawl ---------------- #
    def extract_links(self, url):
        try:
            self.page.goto(url, wait_until="networkidle", timeout=10000)
            links = self.page.eval_on_selector_all(
                "a", "elements => elements.map(e => e.href)"
            )
            return [l for l in links if l and self.target_url in l]
        except:
            return []

    def crawl(self, url=None):
        if url is None:
            url = self.target_url

        links = self.extract_links(url)
        for link in links:
            if link not in self.target_links:
                self.target_links.append(link)
                self.crawl(link)

    # ---------------- Forms ---------------- #
    def extract_forms(self, url):
        try:
            r = self.session.get(url, timeout=5)
            soup = BeautifulSoup(r.text, "html.parser")
            return soup.find_all("form")
        except:
            return []

    def submit_form(self, form, payload, url):
        action = form.get("action")
        post_url = urllib.parse.urljoin(url, action)
        method = form.get("method", "get").lower()

        data = {}
        for input_tag in form.find_all("input"):
            name = input_tag.get("name")
            if name:
                data[name] = payload

        if method == "post":
            return self.session.post(post_url, data=data)
        else:
            return self.session.get(post_url, params=data)

    # ---------------- Vulnerabilities ---------------- #
    def test_xss(self, url):
        payload = "<script>alert(1)</script>"
        test_url = url + "?test=" + payload
        r = self.session.get(test_url)
        if payload in r.text:
            self.vulnerabilities.append(f"XSS found in URL: {url}")

    def test_sqli(self, url):
        payload = "' OR '1'='1"
        test_url = url + "?id=" + payload
        r = self.session.get(test_url)
        errors = ["sql syntax", "mysql", "warning"]
        for err in errors:
            if err in r.text.lower():
                self.vulnerabilities.append(f"SQL Injection found in URL: {url}")

    def check_headers(self):
        r = self.session.get(self.target_url)
        headers = r.headers
        required = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security"
        ]
        for h in required:
            if h not in headers:
                self.vulnerabilities.append(f"Missing Security Header: {h}")

    # ---------------- Run ---------------- #
    def run(self):
        self.crawl()
        self.check_headers()

        for link in self.target_links:
            self.test_xss(link)
            self.test_sqli(link)

            forms = self.extract_forms(link)
            for form in forms:
                payload = "<script>alert(1)</script>"
                response = self.submit_form(form, payload, link)
                if payload in response.text:
                    self.vulnerabilities.append(
                        f"XSS found in form at: {link}"
                    )

        self.browser.close()
        self.playwright.stop()

        return self.vulnerabilities
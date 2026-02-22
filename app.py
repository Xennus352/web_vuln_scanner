from flask import Flask, render_template, request
import requests
import urllib.parse
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from urllib.parse import urlparse

app = Flask(__name__)

class Scanner:
    def __init__(self, target_url):
        if not target_url:
            raise ValueError("Target URL cannot be empty")
        self.target_url = target_url.rstrip("/")
        self.target_links = []
        self.vulnerabilities = []
        self.session = requests.Session()
        self.max_depth = 3  # limit crawl depth

        # Start Playwright
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(headless=True)
        self.page = self.browser.new_page()

    # ---------------- Helper Functions ---------------- #
    def is_valid_http_url(self, url):
        if not url:
            return False
        parsed = urlparse(url)
        return parsed.scheme in ["http", "https"]

    def is_same_domain(self, url):
        return urlparse(url).netloc == urlparse(self.target_url).netloc

    # ---------------- Crawl ---------------- #
    def extract_links(self, url):
        try:
            self.page.goto(url, wait_until="networkidle", timeout=10000)
            links = self.page.eval_on_selector_all(
                "a", "elements => elements.map(e => e.href)"
            )
            # Keep only http(s) links on the same domain
            return [l for l in links if self.is_valid_http_url(l) and self.is_same_domain(l)]
        except:
            return []

    def crawl(self, url=None, depth=0):
        if depth > self.max_depth:
            return
        if url is None:
            url = self.target_url

        links = self.extract_links(url)
        for link in links:
            link = link.rstrip("/")
            if link not in self.target_links:
                self.target_links.append(link)
                self.crawl(link, depth=depth+1)

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
        if not action:
            return None
        post_url = urllib.parse.urljoin(url, action)

        # Ignore javascript, mailto, tel links
        if post_url.startswith(("javascript:", "mailto:", "tel:")):
            return None

        method = form.get("method", "get").lower()
        data = {}
        for input_tag in form.find_all("input"):
            name = input_tag.get("name")
            if name:
                data[name] = payload

        try:
            if method == "post":
                return self.session.post(post_url, data=data, timeout=5)
            else:
                return self.session.get(post_url, params=data, timeout=5)
        except requests.exceptions.RequestException:
            return None

    # ---------------- Vulnerabilities ---------------- #
    def test_xss(self, url):
        payload = "<script>alert(1)</script>"
        try:
            r = self.session.get(url + "?test=" + payload, timeout=5)
            return payload in r.text
        except:
            return False

    def test_sqli(self, url):
        payload = "' OR '1'='1"
        try:
            r = self.session.get(url + "?id=" + payload, timeout=5)
            errors = ["sql syntax", "mysql", "warning"]
            return any(err in r.text.lower() for err in errors)
        except:
            return False

    def test_xss_form(self, form, link):
        payload = "<script>alert(1)</script>"
        response = self.submit_form(form, payload, link)
        return response and payload in response.text

    def check_headers(self):
        try:
            r = self.session.get(self.target_url, timeout=5)
            headers = r.headers
            required = [
                ("Content-Security-Policy", "Warning"),
                ("X-Frame-Options", "Warning"),
                ("Strict-Transport-Security", "Warning")
            ]
            for h, severity in required:
                if h not in headers:
                    self.vulnerabilities.append({
                        "type": severity,
                        "message": f"Missing Security Header: {h}"
                    })
        except:
            pass

    # ---------------- Run ---------------- #
    def run(self):
        self.vulnerabilities = []
        self.crawl()
        self.check_headers()

        for link in self.target_links:
            # XSS
            if self.test_xss(link):
                self.vulnerabilities.append({
                    "type": "Critical",
                    "message": f"XSS found in URL: {link}"
                })
            # SQLi
            if self.test_sqli(link):
                self.vulnerabilities.append({
                    "type": "Critical",
                    "message": f"SQL Injection found in URL: {link}"
                })

            # Forms
            forms = self.extract_forms(link)
            for form in forms:
                if self.test_xss_form(form, link):
                    self.vulnerabilities.append({
                        "type": "Critical",
                        "message": f"XSS found in form at: {link}"
                    })

        # Close Playwright after scan
        self.browser.close()
        self.playwright.stop()
        return self.vulnerabilities

# ---------------- Flask Routes ---------------- #
@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    error = None
    target = None

    if request.method == "POST":
        target = request.form.get("target")

        if not target:
            error = "Please enter a URL."
        elif not target.startswith(("http://", "https://")):
            error = "URL must start with http:// or https://"
        else:
            try:
                scanner = Scanner(target)
                results = scanner.run()
            except Exception as e:
                error = f"Scan failed: {e}"

    return render_template("index.html", results=results, error=error, target=target)

if __name__ == "__main__":
    app.run(debug=True)
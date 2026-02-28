from flask import Flask, render_template, request

from scanner import Scanner

app = Flask(__name__)


def _safe_int(value: str, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


@app.route("/", methods=["GET", "POST"])
def index():
    findings = []
    scan_errors = []
    stats = None
    error = None
    target = ""

    options = {
        "max_depth": 2,
        "max_pages": 60,
    }

    if request.method == "POST":
        target = (request.form.get("target") or "").strip()
        options["max_depth"] = _safe_int(
            request.form.get("max_depth"), default=2, minimum=0, maximum=5
        )
        options["max_pages"] = _safe_int(
            request.form.get("max_pages"), default=60, minimum=10, maximum=300
        )

        if not target:
            error = "Please enter a URL."
        elif not target.startswith(("http://", "https://")):
            error = "URL must start with http:// or https://."
        else:
            try:
                scanner = Scanner(
                    target_url=target,
                    max_depth=options["max_depth"],
                    max_pages=options["max_pages"],
                )
                report = scanner.run()
                findings = report.get("findings", [])
                scan_errors = report.get("errors", [])
                stats = report.get("stats", {})
            except Exception as exc:
                error = f"Scan failed: {exc}"

    return render_template(
        "index.html",
        findings=findings,
        scan_errors=scan_errors,
        stats=stats,
        error=error,
        target=target,
        options=options,
    )


if __name__ == "__main__":
    app.run(debug=True)

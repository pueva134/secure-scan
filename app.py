from flask import Flask, render_template, request
from scanner import run_scan, save_csv_report
import os


app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def do_scan():
    url = request.form.get("url", "").strip()
    if not url:
        return "URL is required", 400

    results = run_scan(url)
    save_csv_report(results)
    return render_template("report.html", results=results)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Render sets PORT
    app.run(host="0.0.0.0", port=port)

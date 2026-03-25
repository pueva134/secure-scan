from flask import Flask, render_template, request
from scanner import run_scan, save_csv_report

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
    save_csv_report(results)   # ← this line adds CSV export
    return render_template("report.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)

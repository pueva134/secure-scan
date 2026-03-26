from flask import Flask, render_template, request
from scanner import run_scan, save_csv_report  # Use REAL functions

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            # Run REAL scanner
            scan_results = run_scan(url)
            save_csv_report(scan_results)  # Auto-save CSV
            
            # Convert to UI format
            vulnerabilities = []
            if scan_results['header_issues']:
                for issue in scan_results['header_issues']:
                    vulnerabilities.append({
                        'title': issue.upper(), 
                        'description': f"Fix: Add {issue.replace('missing ', '')}"
                    })
            if not scan_results['uses_https']:
                vulnerabilities.append({
                    'title': 'HTTPS NOT ENFORCED',
                    'description': 'Enable HSTS and redirect HTTP to HTTPS'
                })
            
            return render_template('results.html', 
                                 results=vulnerabilities, 
                                 scan_data=scan_results,
                                 url=url)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

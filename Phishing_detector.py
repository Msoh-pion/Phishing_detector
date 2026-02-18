# phishing_detector.py
from flask import Flask, request, render_template_string
import re
import whois
from datetime import datetime
import requests
import os

app = Flask(__name__)



template = """
<!DOCTYPE html>
<html>
<head>
    <title>Phishing Detection System</title>
    <style>
        body { font-family: Arial; background: #f8f9fa; text-align: center; padding: 50px; }
        .box { background: white; padding: 30px; border-radius: 12px; width: 420px; margin: auto; 
               box-shadow: 0px 4px 12px rgba(0,0,0,0.2); }
        input { padding: 10px; width: 80%; border-radius: 6px; border: 1px solid #ccc; }
        button { padding: 10px 20px; border: none; border-radius: 6px; 
                 background: #007bff; color: white; cursor: pointer; }
        button:hover { background: #0056b3; }
        .safe { color: green; font-weight: bold; }
        .suspicious { color: orange; font-weight: bold; }
        .phishing { color: red; font-weight: bold; }
    </style>
</head>
<body>
<div style="display:flex; align-items:center; gap:15px;">
 </div>
  <div>
    <h1 style="margin:0;">TVET Trade Fair </h1>

    <p style="margin:0; font-style:italic;">Theme: TVET for Sustainable Development</p>
  </div>
</div>

    <div class="box">
        <h2>🔐 Phishing Detection System 🔐</h2>
        <form method="POST">
            <input type="text" name="url" placeholder="Enter a website URL" required>
            <br><br>
            <button type="submit">Check</button>
        </form>
          <div style="margin-top:30px;">
  <h2 style="font-size:26px; font-weight:bold;">Verdict:</h2>

  <div style="display:flex; gap:20px; margin-top:15px;">
    
    <!-- SAFE -->
    <div style="padding:15px; border:2px solid green; border-radius:10px; width:160px; text-align:center;
    {% if result == 'SAFE ✅' %}background-color:#d4edda; font-weight:bold;{% endif %}">
      ✅ SAFE
    </div>

    <!-- SUSPICIOUS -->
    <div style="padding:15px; border:2px solid orange; border-radius:10px; width:160px; text-align:center;
    {% if result == 'SUSPICIOUS ⚠️' %}background-color:#fff3cd; font-weight:bold;{% endif %}">
      ⚠️ SUSPICIOUS
    </div>

    <!-- PHISHING -->
    <div style="padding:15px; border:2px solid red; border-radius:10px; width:160px; text-align:center;
    {% if result == 'PHISHING 🚨' %}background-color:#f8d7da; font-weight:bold;{% endif %}">
      🚨 PHISHING
    </div>

</div>


<div style="margin-top:40px; padding:15px; background:#eef9f1; border-left:5px solid #2b7a2b; border-radius:8px;">
  <h3>🌍 Why this project matters</h3>
  <p>
    In today’s digital economy, phishing scams threaten financial security and discourage innovation. 
    <p>This project shows how TVET students can apply <ul><p><b>science, technology, and innovation</b> to 
    build cybersecurity solutions that protect individuals and businesses.</p> </p>
    <p>By safeguarding online transactions and digital trust, we contribute directly to:
    <p><b>sustainable development and economic resilience.</b></p>
  </p>
</div>

{% if debug %}
  <h3 style="margin-top:30px; font-size:20px;">Debug Information</h3>
  <pre style="background:#f4f4f4; padding:12px; border-radius:8px; font-size:14px; white-space:pre-wrap;">
{{ debug }}
  </pre>
{% endif %}


    </div>
    <footer style="margin-top:50px; font-size:14px; color:#555; text-align:center;">
  <p>Developed by MATHENGE TTI| ICT Department|ICT INNOVATORS HUB|Cybersecurity Category</p>
</footer>

</body>
</html>
"""

# -------------------------------
# Google Safe Browsing API
# -------------------------------
API_KEY = "AIzaSyAqoo5SjJmbgPcsmo36gVEE-1HQU2aUsFs"  
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

def check_google_safe_browsing(url):
    payload = {
        "client": {"clientId": "tvet-project", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(f"{SAFE_BROWSING_URL}?key={API_KEY}", json=payload)
    result = response.json()
    if "matches" in result:
        return True  # flagged by Google
    return False

# -------------------------------
# Core Phishing Detection Logic
# -------------------------------
def check_url(url):
    score = 0

    # Rule 1: Suspicious characters
    if "@" in url or url.count('-') > 3:
        score += 2

    # Rule 2: Keywords often used in phishing
    phishing_words = ["login", "verify", "update", "secure", "account", "banking", "free", "prize"]
    if any(word in url.lower() for word in phishing_words):
        score += 1

    # Rule 3: Domain registration age
    try:
        domain_info = whois.whois(url)
        if domain_info.creation_date:
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age_days = (datetime.now() - creation_date).days
            if age_days < 180:
                score += 2
    except:
        score += 1

    # Rule 4: Google Safe Browsing check
    try:
        if check_google_safe_browsing(url):
            score += 3  # High weight because it’s from Google’s DB
    except:
        pass  # If API fails, ignore

    # Verdict
    if score <= 1:
        return "SAFE ✅", "safe"
    elif score <= 3:
        return "SUSPICIOUS ⚠️", "suspicious"
    else:
        return "PHISHING 🚨", "phishing"

# Flask Routes
@app.route("/", methods=["GET", "POST"])
def home():
    result, css = None, None
    if request.method == "POST":
        url = request.form["url"].strip()
        result, css = check_url(url)
    return render_template_string(template, result=result, css=css)


if __name__ == "__main__":
    app.run(debug=True)

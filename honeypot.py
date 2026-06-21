import os
import json
import logging
from datetime import datetime
from flask import Flask, request, render_template_string, abort
import requests

# Initialize Flask
app = Flask(__name__)

# Configure Logging Destination
LOG_FILE = os.path.join(os.path.dirname(__file__), "honeypot_attacks.json")

# Ensure log file exists and is formatted as a valid JSON list if empty
if not os.path.exists(LOG_FILE) or os.stat(LOG_FILE).st_size == 0:
    with open(LOG_FILE, "w") as f:
        json.dump([], f)

def get_geo_data(ip_address):
    """
    Queries a free geolocation API to enrich the attacker's IP profile.
    Falls back to 'Local/Unknown' if the IP is local (127.0.0.1) or the API fails.
    """
    if ip_address in ("127.0.0.1", "localhost", "::1"):
        return {"country": "Local Loopback", "city": "Internal Network", "isp": "Self"}
    
    try:
        # Querying the ip-api service (No authentication key required)
        response = requests.get(f"http://ip-api.com{ip_address}", timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown")
                }
    except Exception:
        pass
    return {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}

def log_attack(endpoint_triggered):
    """
    Extracts attacker telemetry, enriches it with geo-indicators, 
    and writes it to the structured JSON log file.
    """
    attacker_ip = request.remote_addr
    geo_indicators = get_geo_data(attacker_ip)
    
    attack_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "attacker_ip": attacker_ip,
        "request_method": request.method,
        "requested_path": request.path,
        "user_agent": request.headers.get("User-Agent", "Missing"),
        "payload_data": request.get_data(as_text=True) or None,
        "endpoint_type": endpoint_triggered,
        "geo_country": geo_indicators["country"],
        "geo_city": geo_indicators["city"],
        "isp": geo_indicators["isp"]
    }
    
    # Thread-safe appending to a JSON array file
    try:
        with open(LOG_FILE, "r+") as f:
            data = json.load(f)
            data.append(attack_entry)
            f.seek(0)
            json.dump(data, f, indent=4)
            f.truncate()
    except Exception as e:
        print(f"Logging Error: {e}")

# --- HONEYPOT ENDPOINTS ---

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def catch_all(path):
    """
    Standard landing page that serves as a generic bait facade.
    Logs standard directory probing / scanning activity.
    """
    log_attack(endpoint_triggered="Standard Decoy Page")
    
    # Generic corporate website placeholder HTML
    decoy_html = """
    <!DOCTYPE html>
    <html>
    <head><title>Under Construction</title></head>
    <body style="font-family: Arial, sans-serif; margin: 50px;">
        <h2>Corporate Intranet Portal</h2>
        <p>This system is restricted to authorised employees only. Unauthorized access is monitored.</p>
    </body>
    </html>
    """
    return render_template_string(decoy_html), 200

@app.route('/admin', methods=['GET', 'POST'])
@app.route('/wp-admin', methods=['GET', 'POST'])
@app.route('/phpmyadmin', methods=['GET', 'POST'])
def high_value_targets():
    """
    High-value decoy assets specifically targets by vulnerability scanners and threat actors.
    Generates a fake login form to extract credential-harvesting data.
    """
    log_attack(endpoint_triggered="High-Value Admin Decoy")
    
    fake_login_html = """
    <!DOCTYPE html>
    <html>
    <head><title>Administrator Authentication</title></head>
    <body style="background-color: #222; color: #fff; font-family: sans-serif; text-align: center; padding-top: 100px;">
        <div style="display: inline-block; width: 300px; padding: 20px; border: 1px solid #444; background: #333;">
            <h3>Internal Admin Console</h3>
            <form method="POST">
                <input type="text" name="user" placeholder="Username" style="width:90%; margin:10px 0; padding:5px;"><br>
                <input type="password" name="pass" placeholder="Password" style="width:90%; margin:10px 0; padding:5px;"><br>
                <button type="submit" style="width:95%; padding:5px; background:#007BFF; color:white; border:none;">Login</button>
            </form>
        </div>
    </body>
    </html>
    """
    return render_template_string(fake_login_html), 401

if __name__ == '__main__':
    # Running on port 5000 internally. Production standard usually requires port 80/443.
    print("[*] Starting Web Honeypot Decoy...")
    app.run(host='0.0.0.0', port=5000, debug=False)

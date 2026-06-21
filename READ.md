# Python Web Honeypot with Global Geo-TI Indicators

A defensive engineering tool built in Python using Flask to log, track, and contextualize malicious web application probing and unauthorized credential harvesting attempts.

## Core Features
* **Decoy Architecture:** Serves structural corporate facades alongside sensitive web route lures (`/admin`, `/wp-admin`, `/phpmyadmin`).
* **Threat Intelligence Enrichment:** Leverages third-party JSON API integrations to trace attacker IP infrastructure back to physical geographic regions (Country, City, ISP).
* **SIEM-Ready Log Aggregation:** Output matches automated security event structures by parsing telemetry directly into structured JSON arrays.

## Code Requirements & Execution
Ensure you have the required modules installed:
\`\`\`bash
pip install -r requirements.txt
python app.py
\`\`\`

## Sample Indicators of Compromise (IoC) Log Output
\`\`\`json
{
    "timestamp": "2026-05-20T18:22:00Z",
    "attacker_ip": "185.190.140.22",
    "request_method": "POST",
    "requested_path": "/admin",
    "user_agent": "Mozilla/5.0 (Hydra Brute-Forcing Utility)",
    "payload_data": "user=admin&pass=Password123",
    "endpoint_type": "High-Value Admin Decoy",
    "geo_country": "Netherlands",
    "geo_city": "Amsterdam",
    "isp": "Leaseweb Hosting"
}
\`\`\`
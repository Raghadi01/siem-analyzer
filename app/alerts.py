import requests
import os
from dotenv import load_dotenv

load_dotenv()

DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK_URL")

SEVERITY_COLORS = {
    "critical": 15158332,
    "high":     15105570,
    "medium":   10181046,
    "low":      3066993
}

def send_discord_alert(incident: dict, incident_id: int):
    if not DISCORD_WEBHOOK:
        print("No Discord webhook configured")
        return

    severity = incident.get("severity", "medium").lower()
    color = SEVERITY_COLORS.get(severity, 10181046)

    embed = {
        "title": f"SIEM Alert — {incident.get('threat_type', 'Unknown Threat')}",
        "color": color,
        "fields": [
            {
                "name": "Severity",
                "value": severity.upper(),
                "inline": True
            },
            {
                "name": "MITRE Technique",
                "value": incident.get("mitre_technique", "Unknown"),
                "inline": True
            },
            {
                "name": "Attacker IP",
                "value": incident.get("attacker_ip", "Unknown"),
                "inline": True
            },
            {
                "name": "Affected User",
                "value": incident.get("affected_user", "Unknown"),
                "inline": True
            },
            {
                "name": "Incident ID",
                "value": f"INC-{incident_id:04d}",
                "inline": True
            },
            {
                "name": "AI Explanation",
                "value": incident.get("explanation", "")[:500],
                "inline": False
            }
        ],
        "footer": {
            "text": "AI-SIEM Analyzer"
        }
    }

    payload = {
        "username": "SIEM Alert Bot",
        "embeds": [embed]
    }

    try:
        response = requests.post(DISCORD_WEBHOOK, json=payload)
        if response.status_code == 204:
            print(f"Discord alert sent for INC-{incident_id:04d}")
        else:
            print(f"Discord alert failed: {response.status_code}")
    except Exception as e:
        print(f"Discord alert error: {e}")

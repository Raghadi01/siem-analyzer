import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def analyze_logs(logs: list) -> dict:
    from app.database import get_ip_history

    log_text = "\n".join([
        f"- service={l['_source'].get('service','unknown')}, "
        f"action={l['_source'].get('action','unknown')}, "
        f"user={l['_source'].get('user', l['_source'].get('affected_user', 'unknown'))}, "
        f"source_ip={l['_source'].get('source_ip','unknown')}, "
        f"url={l['_source'].get('url','')}, "
        f"message={l['_source'].get('message','')}, "
        f"event_id={l['_source'].get('event_id','')}, "
        f"timestamp={l['_source'].get('timestamp','unknown')}"
        for l in logs
    ])

    unique_ips = set(
        l['_source'].get('source_ip', '')
        for l in logs
        if l['_source'].get('source_ip')
    )

    history_text = ""
    for ip in unique_ips:
        if not ip or ip == 'unknown':
            continue
        history = get_ip_history(ip)
        if history:
            history_text += f"\nPrevious incidents from {ip}:\n"
            for h in history:
                history_text += f"  - {h['threat_type']} ({h['severity']}) using {h['mitre_technique']} on {h['created_at']}\n"

    if history_text:
        memory_section = f"""
ATTACKER HISTORY (from previous incidents):
{history_text}
If the same IP appears in history, this is a REPEAT attacker — escalate severity accordingly.
"""
    else:
        memory_section = "\nNo previous incidents found for these IP addresses.\n"

    prompt = f"""
You are an expert cybersecurity analyst working in a SOC.
Analyze these logs from multiple sources and detect ALL threats.

{memory_section}

CURRENT LOGS:
{log_text}

Look for these attack patterns across ALL log types:
- SSH/RDP brute force: multiple failed logins then success
- Web attacks: path traversal, .env exposure, SQL injection, scanner probes
- Persistence: cron jobs with reverse shells, new user creation, scheduled tasks
- Lateral movement: unusual logon types, SMB connections, remote services
- Reconnaissance: port scans, firewall blocks from same IP
- Multi-stage attacks: same IP appearing across different log types

If the same IP appears in multiple log types — that is a multi-stage attack.
If the IP has previous incidents — treat it as a repeat attacker and increase severity.
Identify ALL techniques used, not just the first one you find.

Respond ONLY in this exact JSON format with no other text:
{{
    "threat_detected": true or false,
    "threat_type": "specific name of the attack or combined attack name",
    "severity": "critical, high, medium, or low",
    "mitre_technique": "most relevant MITRE ATT&CK technique ID",
    "affected_user": "username or none",
    "attacker_ip": "attacker IP address or none",
    "explanation": "detailed plain English explanation covering ALL suspicious activities found, including any repeat attacker history"
}}
"""

    response = client.chat.completions.create(
        model=os.getenv("GROQ_MODEL"),
        messages=[{"role": "user", "content": prompt}]
    )

    result = response.choices[0].message.content
    return json.loads(result)

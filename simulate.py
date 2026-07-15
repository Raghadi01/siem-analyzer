import requests
import time
import random
from datetime import datetime, timedelta

API_URL = "http://localhost:8000/logs"

ATTACKERS = {
    "chinese_apt": {
        "ips": ["103.224.182.210", "103.75.190.15", "45.142.212.100"],
        "style": "slow and stealthy — low volume, long gaps",
        "targets": ["admin", "root", "oracle"]
    },
    "russian_botnet": {
        "ips": ["185.220.101.5", "185.220.101.34", "185.220.101.47", "185.220.102.8"],
        "style": "fast and aggressive — high volume brute force",
        "targets": ["root", "administrator", "user"]
    },
    "script_kiddie": {
        "ips": ["192.168.100.55", "10.10.10.200"],
        "style": "noisy and obvious — runs automated tools",
        "targets": ["admin", "test", "guest", "ubuntu"]
    },
    "insider_threat": {
        "ips": ["10.0.0.15", "10.0.0.23"],
        "style": "internal IP — legitimate user doing suspicious things",
        "targets": ["dbadmin", "sysadmin"]
    },
    "web_scanner": {
        "ips": ["198.235.24.130", "66.240.192.138", "71.6.135.131"],
        "style": "automated web scanner probing everything",
        "targets": ["anonymous"]
    }
}

def get_timestamp():
    return datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S")

def build_scenarios(attacker_name: str) -> list:
    attacker = ATTACKERS[attacker_name]
    ip = random.choice(attacker["ips"])
    user = random.choice(attacker["targets"])
    ts = get_timestamp()

    scenarios = {
        "chinese_apt": [
            ("firewall", f"BLOCK {ip} -> 10.0.0.1:22 SYN"),
            ("ssh", f"Failed password for {user} from {ip} port {random.randint(10000,65000)} ssh2"),
            ("nginx", f'{ip} - - [{ts}] "GET /admin HTTP/1.1" 404 162'),
            ("ssh", f"Failed password for {user} from {ip} port {random.randint(10000,65000)} ssh2"),
            ("nginx", f'{ip} - - [{ts}] "GET /.git/config HTTP/1.1" 200 92'),
            ("ssh", f"Accepted password for {user} from {ip} port {random.randint(10000,65000)} ssh2"),
            ("syslog", f"Apr 15 08:00:01 server sshd[1234]: pam_unix: session opened for user {user} by (uid=0)"),
        ],
        "russian_botnet": [
            ("ssh", f"Failed password for {user} from {ip} port {random.randint(10000,65000)} ssh2"),
            ("ssh", f"Failed password for {user} from {ip} port {random.randint(10000,65000)} ssh2"),
            ("ssh", f"Failed password for {user} from {ip} port {random.randint(10000,65000)} ssh2"),
            ("ssh", f"Failed password for {user} from {ip} port {random.randint(10000,65000)} ssh2"),
            ("ssh", f"Failed password for {user} from {ip} port {random.randint(10000,65000)} ssh2"),
            ("rdp", f"RDP failed login for {user} from {ip}"),
            ("rdp", f"RDP failed login for {user} from {ip}"),
            ("ssh", f"Accepted password for {user} from {ip} port {random.randint(10000,65000)} ssh2"),
            ("windows", f"EventID: 4625 | Account: {user} | IP: {ip} | Failure: Wrong password"),
            ("windows", f"EventID: 4624 | Account: {user} | IP: {ip} | Logon Type: 3"),
        ],
        "script_kiddie": [
            ("nginx", f'{ip} - - [{ts}] "GET /phpmyadmin/ HTTP/1.1" 404 162'),
            ("nginx", f'{ip} - - [{ts}] "GET /wp-login.php HTTP/1.1" 200 4521'),
            ("nginx", f'{ip} - - [{ts}] "GET /.env HTTP/1.1" 200 312'),
            ("nginx", f'{ip} - - [{ts}] "GET /admin/../../../etc/passwd HTTP/1.1" 200 1452'),
            ("nginx", f'{ip} - - [{ts}] "POST /wp-login.php HTTP/1.1" 200 4521'),
            ("nginx", f'{ip} - - [{ts}] "GET /shell.php HTTP/1.1" 404 162'),
            ("nginx", f'{ip} - - [{ts}] "GET /backup.zip HTTP/1.1" 404 162'),
        ],
        "insider_threat": [
            ("mysql", f"2026-04-15 08:00:01 {user}@{ip}: SELECT * FROM customers LIMIT 100000"),
            ("mysql", f"2026-04-15 08:00:02 {user}@{ip}: SELECT * FROM credit_cards"),
            ("mysql", f"2026-04-15 08:00:03 {user}@{ip}: SELECT * FROM users"),
            ("firewall", f"ALLOW {ip} -> 185.220.101.5:443 TCP 500MB"),
            ("firewall", f"ALLOW {ip} -> 185.220.101.5:443 TCP 1200MB"),
            ("syslog", f"Apr 15 08:00:04 server sudo[5678]: {user} : TTY=unknown ; PWD=/var/db ; USER=root ; COMMAND=/bin/tar -czf /tmp/backup.tar.gz /var/db"),
        ],
        "web_scanner": [
            ("nginx", f'{ip} - - [{ts}] "GET /robots.txt HTTP/1.1" 200 32'),
            ("nginx", f'{ip} - - [{ts}] "GET /sitemap.xml HTTP/1.1" 200 1242'),
            ("nginx", f'{ip} - - [{ts}] "GET /admin HTTP/1.1" 302 0'),
            ("nginx", f'{ip} - - [{ts}] "GET /api/v1/users HTTP/1.1" 401 45'),
            ("nginx", f'{ip} - - [{ts}] "GET /.env HTTP/1.1" 200 312'),
            ("nginx", f'{ip} - - [{ts}] "GET /api/v1/admin HTTP/1.1" 403 89'),
            ("firewall", f"BLOCK {ip} -> 10.0.0.1:3306 SYN"),
            ("firewall", f"BLOCK {ip} -> 10.0.0.1:6379 SYN"),
            ("firewall", f"BLOCK {ip} -> 10.0.0.1:27017 SYN"),
        ],
    }

    return scenarios.get(attacker_name, [])

def send_log(source: str, message: str):
    try:
        response = requests.post(API_URL, json={
            "source": source,
            "message": message
        })
        if response.status_code == 200:
            data = response.json()
            service = data.get("parsed", {}).get("service", source)
            action = data.get("parsed", {}).get("action", "unknown")
            ip = data.get("parsed", {}).get("source_ip", "unknown")
            print(f"  [{service.upper()}] {action} from {ip} — {message[:50]}...")
        else:
            print(f"  [ERROR] {response.status_code}")
    except Exception as e:
        print(f"  [FAILED] {e}")

def run_attacker(name: str, delay: float = 1.0):
    attacker = ATTACKERS[name]
    ip_used = random.choice(attacker["ips"])
    print(f"\nAttacker: {name.upper()}")
    print(f"Style: {attacker['style']}")
    print(f"IP: {ip_used}")
    print("-" * 50)

    logs = build_scenarios(name)
    for source, message in logs:
        send_log(source, message)
        time.sleep(delay)

    print(f"Attack complete — Celery analyzes in next 60s cycle")

def run_realistic_simulation(duration_minutes: int = 5):
    print(f"\nRealistic simulation — {duration_minutes} minutes of mixed attacks")
    print("Multiple attackers, multiple IPs, random timing")
    print("Press Ctrl+C to stop")
    print("=" * 50)

    attackers = list(ATTACKERS.keys())
    end_time = datetime.utcnow() + timedelta(minutes=duration_minutes)

    while datetime.utcnow() < end_time:
        attacker = random.choice(attackers)
        delay = random.uniform(0.5, 2.0)
        run_attacker(attacker, delay=delay)
        gap = random.randint(5, 15)
        print(f"\nGap between attacks: {gap} seconds...")
        time.sleep(gap)

    print("\nSimulation complete.")

def run_all_attackers():
    print("Running all attacker profiles")
    print("=" * 50)
    for name in ATTACKERS:
        run_attacker(name, delay=0.8)
        time.sleep(3)
    print("\nAll attackers done — wait 60s for Celery analysis")

if __name__ == "__main__":
    print("AI-SIEM Realistic Attack Simulator")
    print("=" * 50)
    print("Attacker profiles:")
    for i, name in enumerate(ATTACKERS.keys(), 1):
        attacker = ATTACKERS[name]
        print(f"  {i}. {name} — {attacker['style']}")
    print(f"  {len(ATTACKERS)+1}. Run all attacker profiles")
    print(f"  {len(ATTACKERS)+2}. Realistic simulation (5 min mixed attacks)")
    print()

    choice = input("Choose (number): ").strip()
    attackers = list(ATTACKERS.keys())

    try:
        idx = int(choice) - 1
        if idx < len(attackers):
            run_attacker(attackers[idx])
        elif idx == len(attackers):
            run_all_attackers()
        elif idx == len(attackers) + 1:
            run_realistic_simulation(5)
    except (ValueError, IndexError):
        print("Invalid choice")

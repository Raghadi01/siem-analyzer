import re
from datetime import datetime

def parse_ssh_log(message: str) -> dict:
    pattern = r"(\w+) password for (\w+) from ([\d.]+) port (\d+)"
    match = re.search(pattern, message)
    if match:
        return {
            "action": match.group(1),
            "user": match.group(2),
            "source_ip": match.group(3),
            "port": int(match.group(4)),
            "service": "ssh",
            "log_type": "auth",
            "timestamp": datetime.utcnow().isoformat(),
            "raw": message,
            "analyzed": False
        }
    return None

def parse_nginx_log(message: str) -> dict:
    pattern = r'([\d.]+) .* "(GET|POST|PUT|DELETE|HEAD) ([^\s]+) HTTP[^"]*" (\d+)'
    match = re.search(pattern, message)
    if match:
        return {
            "source_ip": match.group(1),
            "action": match.group(2),
            "url": match.group(3),
            "status_code": int(match.group(4)),
            "service": "nginx",
            "log_type": "web",
            "timestamp": datetime.utcnow().isoformat(),
            "raw": message,
            "analyzed": False
        }
    return None

def parse_syslog(message: str) -> dict:
    pattern = r"(\w+\s+\d+\s+[\d:]+)\s+(\w+)\s+([^:]+):\s+(.*)"
    match = re.search(pattern, message)
    if match:
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "host": match.group(2),
            "service": match.group(3).strip(),
            "action": "syslog_event",
            "message": match.group(4),
            "log_type": "system",
            "raw": message,
            "analyzed": False
        }
    return None

def parse_windows_event(message: str) -> dict:
    event_id = re.search(r"EventID:\s*(\d+)", message)
    account = re.search(r"Account:\s*(\w+)", message)
    ip = re.search(r"IP:\s*([\d.]+)", message)
    logon_type = re.search(r"Logon Type:\s*(\d+)", message)
    process = re.search(r"Process:\s*([^\|]+)", message)
    failure = re.search(r"Failure:\s*([^\|]+)", message)

    if not event_id:
        return None

    eid = int(event_id.group(1))

    event_map = {
        4624: "Successful logon",
        4625: "Failed logon",
        4634: "Account logoff",
        4648: "Logon with explicit credentials",
        4672: "Special privileges assigned",
        4688: "New process created",
        4698: "Scheduled task created",
        4720: "User account created",
        4726: "User account deleted",
        4732: "User added to group",
        4740: "Account locked out",
        4756: "Member added to security group",
    }

    return {
        "event_id": eid,
        "action": event_map.get(eid, f"Windows event {eid}"),
        "user": account.group(1) if account else "unknown",
        "source_ip": ip.group(1) if ip else "unknown",
        "logon_type": logon_type.group(1) if logon_type else None,
        "process": process.group(1).strip() if process else None,
        "failure_reason": failure.group(1).strip() if failure else None,
        "service": "windows",
        "log_type": "windows_event",
        "timestamp": datetime.utcnow().isoformat(),
        "raw": message,
        "analyzed": False
    }

def parse_firewall_log(message: str) -> dict:
    pattern = r"(BLOCK|ALLOW|DROP|ACCEPT)\s+([\d.]+)\s*[→\->]+\s*([\d.]+):(\d+)"
    match = re.search(pattern, message)
    if match:
        return {
            "action": match.group(1),
            "source_ip": match.group(2),
            "dest_ip": match.group(3),
            "port": int(match.group(4)),
            "service": "firewall",
            "log_type": "network",
            "timestamp": datetime.utcnow().isoformat(),
            "raw": message,
            "analyzed": False
        }
    return None

def parse_ftp_log(message: str) -> dict:
    pattern = r"(FAIL|OK|ERROR)\s+LOGIN.*user=(\w+).*from=([\d.]+)"
    match = re.search(pattern, message, re.IGNORECASE)
    if match:
        return {
            "action": match.group(1),
            "user": match.group(2),
            "source_ip": match.group(3),
            "service": "ftp",
            "log_type": "auth",
            "timestamp": datetime.utcnow().isoformat(),
            "raw": message,
            "analyzed": False
        }
    return None

def parse_rdp_log(message: str) -> dict:
    pattern = r"RDP\s+(failed|success)\w*\s+(?:login\s+)?(?:for\s+)?(\w+)\s+from\s+([\d.]+)"
    match = re.search(pattern, message, re.IGNORECASE)
    if match:
        return {
            "action": "Failed" if "fail" in match.group(1).lower() else "Accepted",
            "user": match.group(2),
            "source_ip": match.group(3),
            "service": "rdp",
            "log_type": "auth",
            "timestamp": datetime.utcnow().isoformat(),
            "raw": message,
            "analyzed": False
        }
    return None

def parse_log(source: str, message: str) -> dict:
    parsers = {
        "ssh":      parse_ssh_log,
        "nginx":    parse_nginx_log,
        "apache":   parse_nginx_log,
        "syslog":   parse_syslog,
        "windows":  parse_windows_event,
        "firewall": parse_firewall_log,
        "ftp":      parse_ftp_log,
        "rdp":      parse_rdp_log,
    }

    if source in parsers:
        result = parsers[source](message)
        if result:
            return result

    for parser in parsers.values():
        result = parser(message)
        if result:
            return result

    return {
        "action": "unknown",
        "service": source,
        "log_type": "unknown",
        "raw": message,
        "timestamp": datetime.utcnow().isoformat(),
        "analyzed": False
    }

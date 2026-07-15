import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def ai_parse_log(source: str, message: str) -> dict:
    prompt = f"""
You are a log parsing engine. Parse this log line and extract all relevant fields.

Source system: {source}
Raw log: {message}

Extract these fields if present:
- timestamp (ISO format if possible)
- - source_ip (the IP address of the client, attacker, or remote host — 
  for nginx logs this is the first IP at the start of the line,
  for docker logs look for any IP in the message)
- destination_ip
- user (username involved)
- action (what happened — Failed, Accepted, GET, POST, DROP, etc)
- service (ssh, nginx, mysql, windows, firewall, docker, ftp, rdp, syslog, etc)
- log_type (auth, web, database, network, system, container)
- status_code (HTTP status if applicable)
- url (if web log)
- port (port number if present)
- query (SQL query if database log)
- event_id (Windows event ID if applicable)
- process (process name if applicable)
- message (any additional context)

Respond ONLY with a valid JSON object. No explanation, no markdown, no backticks.
If a field is not present in the log, omit it entirely.
Always include: service, log_type, action, raw (the original log message).
"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500
        )

        result = response.choices[0].message.content.strip()
        
        if result.startswith("```"):
            result = result.split("```")[1]
            if result.startswith("json"):
                result = result[4:]
        
        parsed = json.loads(result)
        
        parsed["raw"] = message
        parsed["analyzed"] = False
        
        if "service" not in parsed:
            parsed["service"] = source
        if "log_type" not in parsed:
            parsed["log_type"] = "unknown"
        if "action" not in parsed:
            parsed["action"] = "unknown"
            
        return parsed

    except json.JSONDecodeError:
        return {
            "action": "unknown",
            "service": source,
            "log_type": "unknown",
            "raw": message,
            "analyzed": False
        }
    except Exception as e:
        print(f"AI parser error: {e}")
        return {
            "action": "unknown",
            "service": source,
            "log_type": "unknown",
            "raw": message,
            "analyzed": False
        }

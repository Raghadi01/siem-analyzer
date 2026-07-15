from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel
from datetime import datetime
from app.normalization.ai_parser import ai_parse_log
from elasticsearch import Elasticsearch
from app.database import get_connection, save_incident
from app.reports.generator import generate_pdf_report
from app.analysis.analyzer import analyze_logs
import os

app = FastAPI()
es = Elasticsearch("http://localhost:9200")

class RawLog(BaseModel):
    source: str
    message: str

@app.get("/")
def health_check():
    return {"status": "SIEM is running"}

@app.get("/dashboard")
def dashboard():
    return FileResponse("app/dashboard.html")

@app.post("/logs")
def receive_log(log: RawLog):
    parsed = ai_parse_log(log.source, log.message)
    es.index(index="siem-logs", document=parsed)
    return {
        "received": True,
        "stored": True,
        "parsed": parsed
    }
    
    parsed["analyzed"] = False
    es.index(index="siem-logs", document=parsed)
    return {
        "received": True,
        "stored": True,
        "parsed": parsed
    }

@app.get("/logs/recent")
def get_recent_logs():
    result = es.search(index="siem-logs", body={
        "query": {"match_all": {}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": 50
    })
    logs = [hit["_source"] for hit in result["hits"]["hits"]]
    return {"logs": logs}

@app.get("/incidents")
def get_incidents():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, threat_type, severity, mitre_technique,
               attacker_ip, affected_user, created_at
        FROM incidents
        ORDER BY created_at DESC
        LIMIT 50
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return {"incidents": [
        {
            "id": row[0],
            "threat_type": row[1],
            "severity": row[2],
            "mitre_technique": row[3],
            "attacker_ip": row[4],
            "affected_user": row[5],
            "created_at": str(row[6])
        }
        for row in rows
    ]}

@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, threat_type, severity, mitre_technique,
               attacker_ip, affected_user, explanation, created_at
        FROM incidents WHERE id = %s
    """, (incident_id,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    if not row:
        return {"error": "Incident not found"}
    return {
        "id": row[0],
        "threat_type": row[1],
        "severity": row[2],
        "mitre_technique": row[3],
        "attacker_ip": row[4],
        "affected_user": row[5],
        "explanation": row[6],
        "created_at": str(row[7])
    }

@app.get("/stats")
def get_stats():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM incidents")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT severity, COUNT(*) FROM incidents GROUP BY severity")
    severity_counts = dict(cursor.fetchall())
    cursor.execute("""
        SELECT mitre_technique, COUNT(*)
        FROM incidents
        GROUP BY mitre_technique
        ORDER BY COUNT(*) DESC
        LIMIT 5
    """)
    mitre_hits = cursor.fetchall()
    cursor.close()
    conn.close()
    return {
        "total_incidents": total,
        "severity_breakdown": severity_counts,
        "top_mitre_techniques": [
            {"technique": row[0], "count": row[1]}
            for row in mitre_hits
        ]
    }

@app.post("/analyze")
def run_analysis():
    result = es.search(index="siem-logs", body={
        "query": {
            "bool": {
                "should": [
                    {"term": {"analyzed": False}},
                    {"bool": {"must_not": {"exists": {"field": "analyzed"}}}}
                ]
            }
        },
        "size": 50
    })
    logs = result["hits"]["hits"]
    if len(logs) == 0:
        return {"message": "No new logs to analyze", "incident": None}
    incident = analyze_logs(logs)
    incident_id = None
    if incident["threat_detected"]:
        incident_id = save_incident(incident)
        generate_pdf_report(incident_id)
    log_ids = [log["_id"] for log in logs]
    for log_id in log_ids:
        es.update(index="siem-logs", id=log_id, body={
            "doc": {"analyzed": True}
        })
    return {
        "logs_analyzed": len(logs),
        "threat_detected": incident["threat_detected"],
        "incident_id": incident_id,
        "incident": incident
    }

@app.get("/reports/{incident_id}/pdf")
def download_pdf(incident_id: int):
    filename = f"incident_report_{incident_id:04d}.pdf"
    if not os.path.exists(filename):
        generate_pdf_report(incident_id, filename)
    return FileResponse(
        filename,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
@app.get("/investigate/{ip_address}")
def investigate_ip(ip_address: str):
    result = es.search(index="siem-logs", body={
        "query": {
            "term": {"source_ip": ip_address}
        },
        "sort": [{"timestamp": {"order": "asc"}}],
        "size": 100
    })
    
    logs = [hit["_source"] for hit in result["hits"]["hits"]]
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, threat_type, severity, mitre_technique, created_at
        FROM incidents
        WHERE attacker_ip = %s
        ORDER BY created_at DESC
    """, (ip_address,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    
    incidents = [
        {
            "id": row[0],
            "threat_type": row[1],
            "severity": row[2],
            "mitre_technique": row[3],
            "created_at": str(row[4])
        }
        for row in rows
    ]
    
    severity_priority = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    highest = None
    if incidents:
        highest = min(incidents, key=lambda x: severity_priority.get(x["severity"], 99))
    
    return {
        "ip": ip_address,
        "total_logs": len(logs),
        "total_incidents": len(incidents),
        "highest_severity": highest["severity"] if highest else "none",
        "logs": logs,
        "incidents": incidents
    }

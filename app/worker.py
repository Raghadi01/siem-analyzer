import os
from celery import Celery
from celery.schedules import crontab
from dotenv import load_dotenv
from app.alerts import send_discord_alert
load_dotenv()

celery_app = Celery(
    "siem_worker",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)

celery_app.conf.beat_schedule = {
    "analyze-logs-every-60-seconds": {
        "task": "app.worker.run_analysis",
        "schedule": 60.0,
    },
}

celery_app.conf.timezone = "UTC"

@celery_app.task
def run_analysis():
    from elasticsearch import Elasticsearch
    from app.analysis.analyzer import analyze_logs
    from app.database import save_incident
    from app.reports.generator import generate_pdf_report

    es = Elasticsearch("http://localhost:9200")

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
        print("No new logs to analyze")
        return {"status": "no_logs"}

    print(f"Analyzing {len(logs)} logs...")
    incident = analyze_logs(logs)

    incident_id = None
    if incident["threat_detected"]:
        incident_id = save_incident(incident)
        generate_pdf_report(incident_id)
        print(f"Incident saved: {incident['threat_type']} — severity: {incident['severity']}")

        if incident["severity"] in ["critical", "high"]:
            send_discord_alert(incident, incident_id)

    log_ids = [log["_id"] for log in logs]
    for log_id in log_ids:
        es.update(index="siem-logs", id=log_id, body={
            "doc": {"analyzed": True}
        })

    print(f"Marked {len(log_ids)} logs as analyzed")
    return {
        "status": "complete",
        "logs_analyzed": len(log_ids),
        "incident_id": incident_id
    }

import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

def get_connection():
    return psycopg2.connect(
        host="localhost",
        port=5432,
        database="siem",
        user="siem_user",
        password="siem_password"
    )

def create_tables():
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id SERIAL PRIMARY KEY,
            threat_type VARCHAR(100),
            severity VARCHAR(20),
            mitre_technique VARCHAR(20),
            attacker_ip VARCHAR(45),
            affected_user VARCHAR(100),
            explanation TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    
    conn.commit()
    cursor.close()
    conn.close()
    print("Tables created successfully")

def save_incident(incident: dict):
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO incidents 
        (threat_type, severity, mitre_technique, attacker_ip, affected_user, explanation)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (
         incident.get("threat_type", "unknown")[:100],
        incident.get("severity", "low")[:20],
        incident.get("mitre_technique", "unknown")[:20],
        incident.get("attacker_ip", "unknown")[:45],
        incident.get("affected_user", "unknown")[:100],
        incident.get("explanation", "")
    ))
    
    incident_id = cursor.fetchone()[0]
    conn.commit()
    cursor.close()
    conn.close()
    return incident_id


def get_ip_history(ip_address: str) -> list:
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT threat_type, severity, mitre_technique, created_at
        FROM incidents
        WHERE attacker_ip = %s
        ORDER BY created_at DESC
        LIMIT 5
    """, (ip_address,))
    
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return [
        {
            "threat_type": row[0],
            "severity": row[1],
            "mitre_technique": row[2],
            "created_at": str(row[3])
        }
        for row in rows
    ]

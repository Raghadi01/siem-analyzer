from app.database import get_connection
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle



def get_incident(incident_id: int) -> dict:
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
        return None
    
    return {
        "id": row[0],
        "threat_type": row[1],
        "severity": row[2],
        "mitre_technique": row[3],
        "attacker_ip": row[4],
        "affected_user": row[5],
        "explanation": row[6],
        "created_at": row[7]
    }

def generate_markdown_report(incident_id: int) -> str:
    incident = get_incident(incident_id)
    
    if not incident:
        return "Incident not found"
    
    report = f"""# Incident Report — {incident['threat_type']}

**Incident ID:** INC-{incident['id']:04d}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Severity:** {incident['severity'].upper()}

---

## Attack Summary

| Field | Value |
|-------|-------|
| Threat Type | {incident['threat_type']} |
| MITRE Technique | {incident['mitre_technique']} |
| Attacker IP | {incident['attacker_ip']} |
| Affected User | {incident['affected_user']} |
| Detected At | {incident['created_at']} |

---

## AI Analysis

{incident['explanation']}

---

## Recommended Actions

1. Block IP `{incident['attacker_ip']}` at the firewall immediately
2. Reset password for account `{incident['affected_user']}`
3. Review all activity from this IP in the last 24 hours
4. Enable multi-factor authentication on affected account
5. Check for any files created or modified during the session

---

*Report generated automatically by AI-SIEM Analyzer*
"""
    return report


def generate_pdf_report(incident_id: int, filename: str = None):
    incident = get_incident(incident_id)
    if not incident:
        return None
    
    if not filename:
        filename = f"incident_report_{incident_id:04d}.pdf"
    
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    
    title_style = ParagraphStyle(
        'title', parent=styles['Heading1'],
        fontSize=20, spaceAfter=6
    )
    story.append(Paragraph(f"Incident Report — {incident['threat_type']}", title_style))
    story.append(Paragraph(f"INC-{incident['id']:04d} · {incident['severity'].upper()} · {incident['created_at']}", styles['Normal']))
    story.append(Spacer(1, 20))
    
    data = [
        ["Field", "Value"],
        ["MITRE Technique", incident['mitre_technique']],
        ["Attacker IP", incident['attacker_ip']],
        ["Affected User", incident['affected_user']],
        ["Severity", incident['severity'].upper()],
    ]
    
    table = Table(data, colWidths=[150, 300])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#534AB7')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#F5F5F5'), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CCCCCC')),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    
    story.append(table)
    story.append(Spacer(1, 20))
    story.append(Paragraph("AI Analysis", styles['Heading2']))
    story.append(Paragraph(incident['explanation'], styles['Normal']))
    story.append(Spacer(1, 20))
    story.append(Paragraph("Recommended Actions", styles['Heading2']))
    
    actions = [
        f"Block IP {incident['attacker_ip']} at the firewall immediately",
        f"Reset password for account {incident['affected_user']}",
        "Review all activity from this IP in the last 24 hours",
        "Enable multi-factor authentication on affected account",
        "Check for any files created or modified during the session"
    ]
    
    for i, action in enumerate(actions, 1):
        story.append(Paragraph(f"{i}. {action}", styles['Normal']))
        story.append(Spacer(1, 4))
    
    doc.build(story)
    return filename






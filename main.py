from fastapi import FastAPI
from database import SessionLocal
from models import Log, Alert, AuditLog
from pydantic import BaseModel

from detection_service import run_detection
from regex_engine import mask_full_text

from audit_service import (
    generate_hash,
    verify_audit_chain
)

# NEW IMPORT
from ai_service import generate_incident_summary

app = FastAPI()


class AlertUpdate(BaseModel):
    status: str
    assigned_to: str | None = None


# =========================
# Store Logs
# =========================
@app.post("/logs")
def create_log(log: dict):

    db = SessionLocal()

    try:
        # Store log
        new_log = Log(
            source=log.get("source"),
            message=log.get("message"),
            ip=log.get("ip")
        )

        db.add(new_log)
        db.commit()
        db.refresh(new_log)

        # Save ID BEFORE detection (avoids DetachedInstanceError)
        log_id = new_log.id

        # Run Detection Engine
        run_detection(db, new_log)

        return {
            "status": "Log stored successfully",
            "id": log_id
        }

    except Exception as e:
        db.rollback()

        return {
            "status": "error",
            "message": str(e)
        }

    finally:
        db.close()


# =========================
# Get Alerts
# =========================
@app.get("/alerts")
def get_alerts(
    severity: str = None,
    status: str = None,
    type: str = None
):

    db = SessionLocal()

    query = db.query(Alert)

    if severity:
        query = query.filter(Alert.severity == severity)

    if status:
        query = query.filter(Alert.status == status)

    if type:
        query = query.filter(Alert.type == type)

    alerts = query.all()

    result = []

    for alert in alerts:

        result.append({
            "id": alert.id,
            "type": alert.type,
            "severity": alert.severity,
            "message": alert.message,
            "status": alert.status,
            "assigned_to": alert.assigned_to,
            "created_at": alert.created_at,
            "updated_at": alert.updated_at
        })

    db.close()

    return result


# =========================
# Update Alert
# =========================
@app.patch("/alerts/{alert_id}")
def update_alert(alert_id: int, alert: AlertUpdate):

    db = SessionLocal()

    db_alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not db_alert:
        db.close()
        return {"error": "Alert not found"}

    db_alert.status = alert.status
    db_alert.assigned_to = alert.assigned_to

    db.commit()
    db.refresh(db_alert)

    db.close()

    return {
        "message": "Alert updated successfully"
    }


# =========================
# Alert Statistics
# =========================
@app.get("/alerts/summary")
def alert_summary():

    db = SessionLocal()

    total = db.query(Alert).count()

    open_alerts = db.query(Alert).filter(
        Alert.status == "OPEN"
    ).count()

    acknowledged = db.query(Alert).filter(
        Alert.status == "ACKNOWLEDGED"
    ).count()

    resolved = db.query(Alert).filter(
        Alert.status == "RESOLVED"
    ).count()

    closed = db.query(Alert).filter(
        Alert.status == "CLOSED"
    ).count()

    db.close()

    return {
        "total": total,
        "open": open_alerts,
        "acknowledged": acknowledged,
        "resolved": resolved,
        "closed": closed
    }


# =========================
# Verify Audit Chain
# =========================
@app.get("/audit/verify")
def verify_audit():

    db = SessionLocal()

    result = verify_audit_chain(db)

    db.close()

    return result


# =========================
# AI Incident Summary
# =========================
@app.get("/incident-summary")
def incident_summary():

    db = SessionLocal()

    try:

        # Fetch all alerts
        alerts = db.query(Alert).all()

        # Generate AI Summary
        summary = generate_incident_summary(alerts)

        return summary

    except Exception as e:

        return {
            "status": "error",
            "message": str(e)
        }

    finally:

        db.close()
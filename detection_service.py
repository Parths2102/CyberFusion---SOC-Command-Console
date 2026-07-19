from models import Log, Alert
from regex_engine import scan_with_regex
from privacy_monitor import store_pii_findings
from audit_service import write_audit_log

BLACKLISTED_IPS = [
    "192.168.1.50",
    "45.33.32.1",
    "103.21.244.10",
    "185.220.101.25",
    "172.67.201.50",
    "198.51.100.77",
    "91.132.137.88",
    "66.240.192.138",
    "23.129.64.210",
    "104.244.72.115",
    "176.65.148.99"
]


def detect_suspicious_ip(db, log):

    if log.ip in BLACKLISTED_IPS:

        alert = Alert(
            type="Suspicious IP",
            severity="MEDIUM",
            status="OPEN",
            message=f"Blacklisted IP detected: {log.ip}"
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        write_audit_log(
            db=db,
            action="CREATE_ALERT",
            table_name="alerts",
            record_id=alert.id,
            details=alert.message
        )


def detect_brute_force(db, log):

    if not log.message:
        return

    if "failed login" not in log.message.lower():
        return

    failed_count = (
        db.query(Log)
        .filter(
            Log.ip == log.ip,
            Log.message.contains("failed login")
        )
        .count()
    )

    if failed_count >= 5:

        alert = Alert(
            type="Brute Force Attempt",
            severity="HIGH",
            status="OPEN",
            message=f"Multiple failed logins from {log.ip}"
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        write_audit_log(
            db=db,
            action="CREATE_ALERT",
            table_name="alerts",
            record_id=alert.id,
            details=alert.message
        )


def detect_pii_exposure(db, log):

    if not log.message:
        return

    result = scan_with_regex(log.message)

    if result:

        store_pii_findings(db, log, result)
        alert = Alert(
            type="PII Exposure",
            severity="CRITICAL",
            status="OPEN",
            message=f"Sensitive information detected: {', '.join(result.keys())}"
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        write_audit_log(
            db=db,
            action="CREATE_ALERT",
            table_name="alerts",
            record_id=alert.id,
            details=alert.message
        )


def run_detection(db, log):

    detect_suspicious_ip(db, log)
    detect_brute_force(db, log)
    detect_pii_exposure(db, log)
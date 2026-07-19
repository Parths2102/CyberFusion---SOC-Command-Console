from models import AuditLog
import hashlib

GENESIS_HASH = hashlib.sha256(b"GENESIS").hexdigest()


def generate_hash(
    previous_hash,
    action,
    table_name,
    record_id,
    details,
    created_at
):
    payload = (
        f"{previous_hash}|"
        f"{action}|"
        f"{table_name}|"
        f"{record_id}|"
        f"{details}|"
        f"{created_at}"
    )

    return hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()


from datetime import datetime

def write_audit_log(
    db,
    action,
    table_name,
    record_id,
    details
):
    # Get last audit log
    last_log = (
        db.query(AuditLog)
        .order_by(AuditLog.id.desc())
        .first()
    )

    # Set previous hash
    if last_log:
        previous_hash = last_log.current_hash
    else:
        previous_hash = GENESIS_HASH

    # Current timestamp
    created_at = datetime.utcnow()

    # Generate current hash
    current_hash = generate_hash(
        previous_hash=previous_hash,
        action=action,
        table_name=table_name,
        record_id=record_id,
        details=details,
        created_at=created_at
    )

    # Create audit log
    audit = AuditLog(
        action=action,
        table_name=table_name,
        record_id=record_id,
        details=details,
        previous_hash=previous_hash,
        current_hash=current_hash,
        created_at=created_at
    )

    db.add(audit)
    db.commit()
    db.refresh(audit)

    return audit


def shorten_hash(hash_value):
    if not hash_value:
        return ""

    return f"{hash_value[:8]}...{hash_value[-8:]}"


def verify_audit_chain(db):

    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.id.asc())
        .all()
    )

    if not logs:
        return {
            "overall_status": "VALID",
            "message": "No audit records found.",
            "total_records": 0,
            "verified_records": []
        }

    expected_previous_hash = GENESIS_HASH

    results = []
    overall_valid = True

    for log in logs:

        recalculated_hash = generate_hash(
            previous_hash=log.previous_hash,
            action=log.action,
            table_name=log.table_name,
            record_id=log.record_id,
            details=log.details,
            created_at=log.created_at
        )

        status = "VALID"
        reason = ""

        if log.previous_hash != expected_previous_hash:
            status = "INVALID"
            reason = "Previous hash mismatch"
            overall_valid = False

        elif log.current_hash != recalculated_hash:
            status = "TAMPERED"
            reason = "Current hash mismatch"
            overall_valid = False

        results.append({
            "audit_id": log.id,
            "action": log.action,
            "status": status,
            "reason": reason,
            "created_at": log.created_at,

            "previous_hash": shorten_hash(log.previous_hash),
            "current_hash": shorten_hash(log.current_hash)
        })

        expected_previous_hash = log.current_hash

    return {
        "overall_status": "VALID" if overall_valid else "FAILED",
        "total_records": len(logs),
        "verified_records": results
    }
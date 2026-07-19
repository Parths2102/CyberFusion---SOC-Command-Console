from models import PIIFinding


def get_pii_risk(pii_type):
   
    risk_map = {
        "Aadhaar Number": "CRITICAL",
        "PAN Card": "HIGH",
        "Bank Account Number": "HIGH",
        "Email Address": "MEDIUM",
        "Mobile Number": "MEDIUM",
        "VPA / UPI ID": "MEDIUM",
        "IP Address": "MEDIUM"
    }

    return risk_map.get(pii_type, "LOW")


def store_pii_findings(db, log, findings):
   
    for pii_type, values in findings.items():

        for value in values:

            finding = PIIFinding(
                log_id=log.id,
                pii_type=pii_type,
                original_value=value,
                masked_value=value,
                risk=get_pii_risk(pii_type)
            )

            db.add(finding)

    db.commit()
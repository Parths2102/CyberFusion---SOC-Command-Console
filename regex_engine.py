"""
regex_engine.py  —  PII detection + masking engine
====================================================
Features
--------
* 20 built-in Indian PII patterns (Aadhaar, PAN, GST, UPI, …)
* Per-pattern confidence scoring  (HIGH / MEDIUM / LOW)
* Three redaction modes: mask  |  tokenise  |  remove
* scan_with_regex()    → {pii_type: [masked_value, …]}
* scan_with_metadata() → rich list of ScanHit objects
* mask_full_text()     → inline redaction of full document
* get_all_patterns()   → raw pattern dict (used by app.py)
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Literal


_BUILTIN: dict[str, tuple[str, str]] = {
    
    "Aadhaar Number":      (r'\b\d{4}\s\d{4}\s\d{4}\b|\b\d{12}\b',"HIGH"),
    "PAN Card":            (r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',"HIGH"),
    "Passport Number":     (r'\b[A-Z][0-9]{7}\b',"HIGH"),
    "Driving Licence":     (r'\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{7}\b',"HIGH"),
    "Voter ID":            (r'\b[A-Z]{3}[0-9]{7}\b',"MEDIUM"),

    
    "Credit Card":         (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',"HIGH"),
    "Bank Account Number": (r'\b\d{9,18}\b',"MEDIUM"),
    "IFSC Code":           (r'\b[A-Z]{4}0[A-Z0-9]{6}\b',"MEDIUM"),
    "GST Number":          (r'\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b',"HIGH"),
    "VPA / UPI ID":        (r'\b[a-zA-Z0-9._-]+@[a-zA-Z0-9]+\b',"MEDIUM"),

    
    "Mobile Number":       (r'\b(?:\+91[\-\s]?)?[6-9]\d{9}\b',"HIGH"),
    "Email Address":       (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',"HIGH"),

    
    "IP Address":          (r'\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b',"HIGH"),
    "IPv6 Address":        (r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',"HIGH"),

    
    "Employee ID":         (r'\bEMP\d+\b',"MEDIUM"),
    "Order ID":            (r'\b(?:ORD|ORDER|Order)[-\s]?\d{3,10}\b',"MEDIUM"),

    
    "Date of Birth":       (r'\b(?:0?[1-9]|[12]\d|3[01])[\/\-](?:0?[1-9]|1[0-2])[\/\-](?:19|20)\d{2}\b', "MEDIUM"),
    "PIN Code":            (r'\b[1-9][0-9]{5}\b',"LOW"),
    "Vehicle Number":      (r'\b[A-Z]{2}\d{2}[A-Z]{1,2}\d{4}\b',"MEDIUM"),
    "Age":                 (r'\b(?:age|aged|dob)[:\s]+(\d{1,3})\b',"LOW"),
}


@dataclass
class ScanHit:
    pii_type:   str
    raw_value:  str
    masked:     str
    confidence: str      # HIGH / MEDIUM / LOW
    start:      int      # char offset in original text
    end:        int
    context:    str = "" # surrounding snippet (±30 chars)

    def to_dict(self) -> dict:
        return {
            "pii_type":   self.pii_type,
            "raw_value":  self.raw_value,
            "masked":     self.masked,
            "confidence": self.confidence,
            "start":      self.start,
            "end":        self.end,
            "context":    self.context,
        }


#  REDACTION

RedactionMode = Literal["mask", "tokenise", "remove"]

_token_vault: dict[str, str] = {}


def get_token_vault() -> dict[str, str]:
    return dict(_token_vault)


def detokenise(token: str) -> str | None:
    return _token_vault.get(token)


def _mask_value(pii_type: str, m: str, mode: RedactionMode = "mask") -> str:

    if mode == "remove":
        return "[REDACTED]"

    if mode == "tokenise":
        token = f"[TKN-{pii_type[:3].upper()}-{uuid.uuid4().hex[:8].upper()}]"
        _token_vault[token] = m
        return token

    #  mask 
    if pii_type == "Aadhaar Number":
        num = m.replace(" ", "")
        return f"XXXX XXXX {num[-4:]}"

    if pii_type == "PAN Card":
        return m[:5] + "****" + m[-1]

    if pii_type == "Mobile Number":
        digits = re.sub(r'\D', '', m)
        return "XXXXXX" + digits[-4:]

    if pii_type == "Email Address":
        name, domain = m.split("@", 1)
        masked_name = name[:2] + "****" if len(name) > 2 else "****"
        return masked_name + "@" + domain

    if pii_type == "Passport Number":
        return m[0] + "XXXXXX" + m[-1]

    if pii_type == "Voter ID":
        return m[:3] + "XXXXX" + m[-2:]

    if pii_type == "Bank Account Number":
        return "XXXXXX" + m[-4:]

    if pii_type == "IFSC Code":
        return m[:4] + "0XXXXXX"

    if pii_type == "Employee ID":
        return "EMP****"

    if pii_type == "Order ID":
        prefix_match = re.match(r'(ORD|ORDER|Order)', m, re.IGNORECASE)
        prefix = prefix_match.group(1).upper() if prefix_match else "ORD"
        digits = re.sub(r'\D', '', m)
        return f"{prefix}****{digits[-3:]}"

    if pii_type == "Credit Card":
        digits = re.sub(r'\D', '', m)
        return "XXXX XXXX XXXX " + digits[-4:]

    if pii_type == "IP Address":
        parts = m.split(".")
        return ".".join(parts[:3]) + ".XXX"

    if pii_type == "IPv6 Address":
        segments = m.split(":")
        return ":".join(segments[:2]) + ":****:****:****:****:****"

    if pii_type == "GST Number":
        return m[:2] + "XXXXXXXXX" + m[-2:]

    if pii_type == "Driving Licence":
        return m[:4] + "****" + m[-3:]

    if pii_type == "VPA / UPI ID":
        handle, bank = m.split("@", 1)
        return handle[:2] + "****@" + bank

    if pii_type == "Date of Birth":
        return "DD/MM/XXXX"

    if pii_type == "PIN Code":
        return m[:2] + "XXXX"

    if pii_type == "Vehicle Number":
        return m[:4] + "****"

    if pii_type == "Age":
        return "[AGE REDACTED]"

    # Fallback
    visible = min(2, len(m) // 3)
    return m[:visible] + "****" + m[-visible:] if visible else "****"


def get_all_patterns() -> dict[str, str]:
    """Return label → regex string for all built-in patterns."""
    return {k: v[0] for k, v in _BUILTIN.items()}


def get_confidence(pii_type: str) -> str:
    return _BUILTIN.get(pii_type, ("", "MEDIUM"))[1]


def scan_with_regex(
    text: str,
    allowed_types: list[str] | None = None,
    mode: RedactionMode = "mask",
) -> dict[str, list[str]]:
    """Return {pii_type: [masked_value, …]}."""
    report: dict[str, list[str]] = {}
    for pii_type, (pattern, _conf) in _BUILTIN.items():
        if allowed_types and pii_type not in allowed_types:
            continue
        matches = re.findall(pattern, text, re.IGNORECASE)
        if not matches:
            continue
        seen: dict[str, str] = {}
        for m in matches:
            if m not in seen:
                seen[m] = _mask_value(pii_type, m, mode)
        report[pii_type] = list(seen.values())
    return report


def scan_with_metadata(
    text: str,
    allowed_types: list[str] | None = None,
    mode: RedactionMode = "mask",
) -> list[ScanHit]:
    """Return list of ScanHit objects sorted by start offset."""
    hits: list[ScanHit] = []
    for pii_type, (pattern, confidence) in _BUILTIN.items():
        if allowed_types and pii_type not in allowed_types:
            continue
        for m in re.finditer(pattern, text, re.IGNORECASE):
            raw = m.group()
            s, e = m.start(), m.end()
            cs = max(0, s - 30)
            ce = min(len(text), e + 30)
            ctx = ("…" if cs > 0 else "") + text[cs:ce] + ("…" if ce < len(text) else "")
            hits.append(ScanHit(
                pii_type   = pii_type,
                raw_value  = raw,
                masked     = _mask_value(pii_type, raw, mode),
                confidence = confidence,
                start      = s,
                end        = e,
                context    = ctx,
            ))
    hits.sort(key=lambda h: h.start)
    return hits


def mask_full_text(
    text: str,
    allowed_types: list[str] | None = None,
    mode: RedactionMode = "mask",
) -> str:
    """Apply masking inline; replaces right-to-left to keep offsets valid."""
    hits = scan_with_metadata(text, allowed_types=allowed_types, mode=mode)
    for hit in reversed(hits):
        text = text[:hit.start] + hit.masked + text[hit.end:]
    return text

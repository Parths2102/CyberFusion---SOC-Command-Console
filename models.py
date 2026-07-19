from sqlalchemy import Column, Integer, String, Text, TIMESTAMP
from sqlalchemy.sql import func
from sqlalchemy.orm import declarative_base
from sqlalchemy import ForeignKey

Base = declarative_base()


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(100))
    message = Column(Text)
    ip = Column(String(50))
    created_at = Column(TIMESTAMP, server_default=func.now())

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String(100))
    severity = Column(String(20))
    message = Column(Text)
    status = Column(String(20), default="OPEN")
    created_at = Column(TIMESTAMP, server_default=func.now())
    assigned_to = Column(String(100), nullable=True)
    updated_at = Column(TIMESTAMP,server_default=func.now(),onupdate=func.now())

class PIIFinding(Base):
    __tablename__ = "pii_findings"

    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, ForeignKey("logs.id"))
    pii_type = Column(String(100))
    original_value = Column(Text)
    masked_value = Column(Text)
    risk = Column(String(20))
    detected_at = Column(TIMESTAMP, server_default=func.now())

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(100))
    table_name = Column(String(100))
    record_id = Column(Integer)
    details = Column(Text)
    previous_hash = Column(Text)
    current_hash = Column(Text)
    created_at = Column(TIMESTAMP, server_default=func.now())


# Technologies demonstrated

# This project shows practical experience with:

# Python
# FastAPI
# PostgreSQL
# SQLAlchemy
# React
# REST APIs
# SHA-256 cryptography
# Regex-based detection
# Security analytics
# Incident response workflows
# Audit logging
# AI-assisted summarization
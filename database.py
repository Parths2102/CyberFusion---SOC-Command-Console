from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base

DATABASE_URL = "postgresql://cyberuser:cyber123@localhost:5432/cyberfusion"

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base.metadata.create_all(bind=engine)



# So far, you've completed:

# ✅ Log Generator
# ✅ FastAPI Log Ingestion
# ✅ Logs Table
# ✅ Detection Engine (3 Rules)

# Brute Force
# Suspicious IP
# PII Exposure

# ✅ Regex Engine

# Detects and masks PII

# ✅ Privacy Monitor

# Stores findings in pii_findings
# Assigns risk

# ✅ Alerts Table

# Status (OPEN)

# At this point, your architecture looks like:

# Log Generator
#       │
#       ▼
# FastAPI
#       │
#       ▼
# Logs Table
#       │
#       ▼
# Detection Engine
#       ├─────────────┐
#       │             │
#       ▼             ▼
# PII Findings     Alerts
# Next Phase (Recommended)
# Phase 4 — Audit Ledger (Tamper-Proof Logging)

# This is the biggest feature that makes your project stand out.

# Why?

# Imagine someone hacks your database.

# They delete:

# Brute Force Alert

# or

# PII Exposure Alert

# How do you know?

# Answer:

# Audit Ledger

# Every important action is permanently recorded.

# New Flow
# Log Stored
#       │
#       ▼
# Detection
#       │
#       ▼
# Alert Created
#       │
#       ▼
# Audit Log Created
# Step 1

# Create a new table

# audit_logs

# Columns

# Column	Purpose
# id	Primary Key
# action	What happened
# table_name	Which table changed
# record_id	Record ID
# details	Description
# previous_hash	Previous record hash
# current_hash	Current record hash
# created_at	Timestamp
# Step 2

# Create

# audit_service.py

# Inside it

# write_audit_log()
# Step 3

# Whenever something important happens

# Instead of only

# Create Alert

# also do

# Create Alert

# ↓

# Write Audit Entry
# Example

# When

# Suspicious IP

# creates an alert

# also write

# Action:
# CREATE_ALERT

# Table:
# alerts

# Record:
# 15

# Details:
# Suspicious IP detected
# Step 4

# Hash Chaining

# This is the interesting part.

# Audit record 1

# hash1

# Audit record 2

# hash(previous_hash + data)

# Audit record 3

# hash(previous_hash + data)

# Now every record depends on the previous one.

# If someone edits record #2

# ↓

# Hash changes

# ↓

# Record #3 no longer matches

# ↓

# Tampering detected.

# Final Architecture
# Log Generator
#         │
#         ▼
# FastAPI
#         │
#         ▼
# Logs Table
#         │
#         ▼
# Detection Engine
#         │
#  ┌──────┼───────────┐
#  │      │           │
#  ▼      ▼           ▼
# Alerts  PII Findings Audit Logs
# After Audit Ledger

# Then move to Phase 5 – AI Incident Summary.

# The flow becomes:

# Log Generated
#       ↓
# Detection
#       ↓
# PII Findings
#       ↓
# Alerts
#       ↓
# Audit Ledger
#       ↓
# AI Summary

# The AI summary can produce something like:

# Incident Summary

# Between 10:00 PM and 10:15 PM:

# 6 Brute Force Attempts detected from IP 192.168.1.50
# 4 Suspicious IP alerts generated
# 3 PII exposures detected (PAN and Aadhaar)

# Recommended Actions:

# Block the source IP.
# Rotate affected credentials.
# Investigate the application that logged sensitive information.
# What I recommend

# Your project is already at a solid stage. The next priorities should be:

# ✅ Audit Ledger (tamper-proof logging)
# ✅ AI Incident Summary (using an LLM)
# ✅ Dashboard (React or Streamlit) to visualize logs, alerts, PII findings, and audit logs
# ✅ Alert management (ACKNOWLEDGED, RESOLVED) and filtering


# How a real SOC works

# Imagine there are three analysts:

# Alice
# Bob
# Charlie

# All three open the SOC dashboard.

# The dashboard calls:

# GET /alerts

# The response might be:

# ID	Type	Severity	Status	Assigned To
# 116	PII Exposure	CRITICAL	OPEN	NULL
# 117	Brute Force	HIGH	OPEN	NULL
# 118	Suspicious IP	MEDIUM	ACKNOWLEDGED	Alice

# Everyone sees the same alerts because they all read from the same database.

# Alice takes Alert 116

# She clicks a button on the dashboard:

# Take Ownership

# The frontend sends:

# PATCH /alerts/116

# Body:

# {
#     "status":"ACKNOWLEDGED",
#     "assigned_to":"Alice"
# }

# Database becomes:

# ID	Status	Assigned To
# 116	ACKNOWLEDGED	Alice

# Now Bob refreshes his dashboard.

# He sees:

# ID	Status	Assigned To
# 116	ACKNOWLEDGED	Alice

# He knows:

# Alice is already working on this alert.

# So he chooses another one.

# Alice investigates

# During investigation, the status stays:

# ACKNOWLEDGED

# She may spend 5 minutes or 2 hours investigating.

# Alice finishes

# She clicks:

# Resolve Alert

# Frontend sends:

# PATCH /alerts/116

# Body:

# {
#     "status":"RESOLVED",
#     "assigned_to":"Alice"
# }

# Database:

# ID	Status
# 116	RESOLVED
# Manager reviews

# Many SOCs don't immediately close alerts.

# Flow becomes:

# OPEN

# ↓

# ACKNOWLEDGED

# ↓

# RESOLVED

# ↓

# CLOSED

# Why?

# The manager may verify:

# Was the incident handled correctly?
# Was documentation completed?
# Were indicators of compromise recorded?

# If everything is complete:

# PATCH /alerts/116
# {
#     "status":"CLOSED",
#     "assigned_to":"Alice"
# }
# How the dashboard looks
# ------------------------------------------------------------
#  SOC ALERT DASHBOARD
# ------------------------------------------------------------

# Severity : [ALL ▼]
# Status   : [OPEN ▼]
# Search   : [____________]

# ------------------------------------------------------------
# ID   TYPE            STATUS         ASSIGNED
# ------------------------------------------------------------
# 116  PII Exposure    OPEN           -
# 117  Brute Force     OPEN           -
# 118  SQL Injection   ACKNOWLEDGED   Alice
# 119  XSS             RESOLVED       Bob
# ------------------------------------------------------------
# Analyst clicks one row

# Example:

# Alert #116

# The right panel opens:

# ---------------------------------

# Alert ID : 116

# Type : PII Exposure

# Severity : CRITICAL

# Message :
# Sensitive information detected

# Status :
# [ OPEN ▼ ]

# Assigned To :
# [ Alice ]

# [ Save Changes ]

# ---------------------------------

# Changing the dropdown from OPEN to ACKNOWLEDGED and clicking Save Changes calls your existing PATCH /alerts/{id} API.

# How does the dashboard stay updated?

# There are two common approaches:

# Option 1: Refresh every few seconds (simplest)

# Every 5 or 10 seconds, the frontend calls:

# GET /alerts

# If Alice changes an alert, Bob sees the update after the next refresh.

# This is easy to build and is enough for many student projects.

# Option 2: Real-time updates (advanced)

# The backend pushes updates instantly using WebSockets.

# As soon as Alice clicks ACKNOWLEDGED, Bob's screen updates immediately without refreshing.

# This is how many enterprise SOC platforms work, but it's an advanced feature.



# Right now, you're testing the backend using Swagger. Later, the dashboard will call the same APIs when users click buttons or choose options from dropdowns.

# Example Dashboard
# --------------------------------------------------------
#                  SOC Alert Dashboard
# --------------------------------------------------------

# Severity :  [ ALL ▼ ]

# Status   :  [ OPEN ▼ ]

# Type      : [ ALL ▼ ]

#              [ Search ]

# --------------------------------------------------------
# ID   Type              Severity    Status
# --------------------------------------------------------
# 116  PII Exposure      CRITICAL    OPEN
# 117  Brute Force       HIGH        OPEN
# 118  Suspicious IP     MEDIUM      ACKNOWLEDGED
# --------------------------------------------------------

# When the analyst changes the dropdown:

# Status ▼

# OPEN
# ACKNOWLEDGED
# RESOLVED
# CLOSED

# and selects ACKNOWLEDGED, the frontend sends:

# GET /alerts?status=ACKNOWLEDGED

# The backend returns only acknowledged alerts.

# Another example

# If the analyst selects:

# Severity ▼

# HIGH

# the frontend calls:

# GET /alerts?severity=HIGH

# The backend returns only HIGH severity alerts.

# Updating an alert

# Suppose the analyst clicks on Alert 116.

# A details panel opens:

# Alert ID : 116

# Type : PII Exposure

# Severity : CRITICAL

# Status

# ▼ ACKNOWLEDGED

# Assigned To

# Alice

# [ Save ]

# When the analyst clicks Save, the frontend calls:

# PATCH /alerts/116

# with:

# {
#     "status": "ACKNOWLEDGED",
#     "assigned_to": "Alice"
# }
# Alert Summary Dashboard

# At the top of the dashboard, you can show small cards:

# +----------------+  +------------------+  +----------------+
# | Total Alerts   |  | Open Alerts      |  | Resolved       |
# |      26        |  |        18        |  |       7        |
# +----------------+  +------------------+  +----------------+

# These values come from:

# GET /alerts/summary
# Backend vs Frontend

# Right now, you're building the backend.

# Your backend provides these APIs:

# ✅ GET /alerts → List alerts.
# ✅ GET /alerts?status=OPEN → Filter alerts.
# ✅ PATCH /alerts/{id} → Update alert status and assignment.
# ✅ GET /alerts/summary → Dashboard statistics.

# Later, when you build the frontend (using React, HTML/CSS/JavaScript, or another framework), you'll add:

# Dropdowns for Status, Severity, and Type.
# Buttons like Take Ownership, Resolve, and Close.
# Summary cards showing alert counts.
# A table that refreshes automatically every few seconds or when the user clicks Refresh


# Step 6: Run FastAPI
# uvicorn main:app --reload
# Step 7: Generate a new alert

# Call

# POST /logs

# with any log that creates an alert.

# Example:

# {
#     "source":"Firewall",
#     "message":"User PAN ABCDE1234F found",
#     "ip":"45.33.32.1"
# }

# This should create:

# ✅ Suspicious IP alert
# ✅ PII Exposure alert
# ✅ Audit entries for each alert
# Step 8: Verify

# Run in PostgreSQL:

# SELECT id,action,table_name,record_id,details
# FROM audit_logs;

# Expected output:

#  id |    action     | table_name | record_id | details
# ----+---------------+------------+-----------+-----------------------------------------
#  1  | CREATE_ALERT  | alerts     | 117       | Blacklisted IP detected: 45.33.32.1
#  2  | CREATE_ALERT  | alerts     | 118       | Sensitive information detected: PAN Card
# After this is working, the next step is to also write audit logs when an alert is updated.

# For example, in your PATCH /alerts/{id} API:

# When status changes to ACKNOWLEDGED → write an audit log with action ACKNOWLEDGE_ALERT.
# When status changes to RESOLVED → write an audit log with action RESOLVE_ALERT.
# Later, when you support CLOSED, write another audit log with action CLOSE_ALERT.

# After that, we'll replace the empty previous_hash and current_hash values with a real SHA-256 hash chain, which is the tamper-evident feature interviewers often find memorable.
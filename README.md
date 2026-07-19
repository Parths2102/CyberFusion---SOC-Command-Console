🛡️ CyberFusion SOC Dashboard

📖 Overview
CyberFusion is a full-stack Security Operations Center (SOC) simulation that demonstrates real-time cybersecurity monitoring, threat detection, incident response, audit logging, and AI-powered incident analysis.

Built with FastAPI, React, PostgreSQL, and Groq LLM, it provides a realistic SOC workflow for learning and demonstration purposes.

✨ Features
- 📊 Real-time security log monitoring
- 🚨 Automatic threat detection
- 🔐 JWT-based user authentication
- 🕵️ PII detection and data masking
- 🔗 Tamper-proof audit logging using SHA-256 hash chaining
- 🤖 AI-generated incident summaries
- 📈 Interactive dashboard with charts and analytics
- ⚡ Manual and automatic log generation

🚨 Detection Rules
- Suspicious IP Detection
- Brute Force Attack Detection
- PII Exposure Detection
- Multi-Stage Attack Correlation

🤖 AI Incident Summary
Powered by Groq Llama 3.3 70B to generate:
- Incident Summary
- Risk Assessment
- Attack Statistics
- Recommended Actions

📊 Dashboard Modules
- Security Overview
- Alert Management
- AI Incident Brief
- Audit Ledger
- Log Simulator

🛠️ Tech Stack
 Backend
- FastAPI
- Python
- SQLAlchemy
- PostgreSQL
- Groq API

Frontend
- React
- Vite
- Recharts
- Axios

Security
- JWT Authentication
- SHA-256 Audit Chain
- Regex-based PII Detection

🔄 Workflow
1. Logs are ingested into the system.
2. The detection engine analyzes each log.
3. Alerts and PII findings are generated.
4. Audit records are securely stored.
5. AI creates an incident summary.
6. The dashboard displays real-time insights.

🎯 Key Highlights
- Real-time SOC simulation
- AI-assisted incident reporting
- Tamper-proof audit ledger
- Automated PII detection and masking
- Multi-stage attack detection
- Interactive security dashboard
- Clean and scalable architecture

🚀 Future Improvements
- WebSocket-based live updates
- MITRE ATT&CK Mapping
- Threat Intelligence Integration
- Role-Based Access Control (RBAC)
- Machine Learning-based anomaly detection

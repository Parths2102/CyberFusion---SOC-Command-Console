import json
from groq import Groq
from config import GROQ_API_KEY

client = Groq(api_key=GROQ_API_KEY)

def generate_incident_summary(alerts):
    """
    Generates AI-powered incident summary from alerts.
    Returns clean dict for FastAPI.
    """
    if not alerts:
        return {
            "summary": "No security incidents detected.",
            "top_attack": "None",
            "critical_alerts": 0,
            "high_alerts": 0,
            "affected_ips": [],
            "recommendations": ["Continue monitoring the infrastructure."]
        }

    critical = 0
    high = 0
    alert_text = ""
    ips = set()

    for i, alert in enumerate(alerts, start=1):
        if alert.severity.lower() == "critical":
            critical += 1
        if alert.severity.lower() == "high":
            high += 1

        # Extract IP from message if possible (fallback)
        import re
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', alert.message or "")
        ip = ip_match.group(0) if ip_match else None

        if ip and ip not in ["127.0.0.1", "localhost"]:
            ips.add(ip)

        alert_text += f"""Alert {i}
Severity: {alert.severity}
Type: {alert.type}
Message: {alert.message}
Source IP: {ip or "N/A"}
Time: {alert.created_at}
----------------------------------------
"""

    prompt = f"""You are an expert SOC Analyst.
Analyze the following security alerts and generate a concise incident summary.

Security Alerts:
{alert_text}

Return ONLY valid JSON in this exact format (no markdown, no extra text):
{{
    "summary": "2-3 professional sentences summarizing the incident.",
    "top_attack": "Most prominent attack type (e.g., Brute Force, PII Exposure, Suspicious IP)",
    "critical_alerts": {critical},
    "high_alerts": {high},
    "affected_ips": {list(ips)[:10]},  // limit to top 10
    "recommendations": ["rec1", "rec2", "rec3", "rec4"]
}}
"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a professional SOC Analyst. Always respond with valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=800
        )

        result_text = response.choices[0].message.content.strip()

        # Clean possible markdown/code block wrappers
        if result_text.startswith("```json"):
            result_text = result_text.split("```json")[1].split("```")[0].strip()
        elif result_text.startswith("```"):
            result_text = result_text.split("```")[1].strip()

        summary_dict = json.loads(result_text)

        # Ensure structure is complete
        summary_dict.setdefault("affected_ips", list(ips)[:10])
        summary_dict.setdefault("recommendations", [
            "Block malicious IPs immediately.",
            "Enforce Multi-Factor Authentication (MFA).",
            "Investigate systems with PII exposure.",
            "Review and strengthen DLP controls."
        ])

        return summary_dict

    except json.JSONDecodeError as e:
        print("JSON Parse Error:", str(e))
        print("Raw Groq output:", result_text)
        return fallback_summary(critical, high, ips)
    except Exception as e:
        print("Groq API Error:", str(e))
        return fallback_summary(critical, high, ips)


def fallback_summary(critical, high, ips):
    return {
        "summary": "Multiple security alerts detected. AI summarization encountered an error. Manual review recommended.",
        "top_attack": "Mixed Threats (Brute Force + PII Exposure + Suspicious IPs)",
        "critical_alerts": critical,
        "high_alerts": high,
        "affected_ips": list(ips)[:10],
        "recommendations": [
            "Block all suspicious IPs listed.",
            "Enforce MFA on all accounts.",
            "Investigate PII exposure incidents urgently.",
            "Conduct full log analysis and strengthen monitoring."
        ]
    }
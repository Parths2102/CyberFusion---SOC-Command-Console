import requests
import random
import time

URL = "http://127.0.0.1:8000/logs"

sources = ["auth_service", "api_gateway", "system", "ids"]

def fake_aadhaar():
    return f"{random.randint(1000,9999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}"

def fake_phone():
    return f"+91-{random.randint(9000000000,9999999999)}"

def fake_email():
    names = ["rahul", "john", "alice", "user", "admin"]
    domains = ["gmail.com", "test.com", "company.com"]
    return f"{random.choice(names)}{random.randint(1,999)}@{random.choice(domains)}"

def fake_pan():
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return (
        "".join(random.choices(letters, k=5))
        + str(random.randint(1000,9999))
        + random.choice(letters)
    )

MALICIOUS_IPS = [
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

def generate_message(user_id):

    category = random.choice([
        "normal",
        "brute_force",
        "suspicious_ip",
        "pii_exposure"
    ])

    if category == "normal":
        return category, random.choice([
        
        f"user_{user_id} login success",
        f"user_{user_id} logout successful",
        f"user_{user_id} password changed successfully",
        f"user_{user_id} accessed profile",

        "GET /api/data",
        "POST /api/orders",
        "GET /api/products",
        "PUT /api/profile",
        "DELETE /api/cart",

        "CPU usage high",
        "Memory usage normal",
        "Disk cleanup completed",
        "System backup completed",
        "Application service restarted",

        "Database connection established",
        "Database backup completed",
        "Executed SELECT query",
        "Database connection closed",

        "DNS lookup successful",
        "Network latency within threshold",
        "Firewall rule updated",
        "VPN connection established",

        "File uploaded successfully",
        "File downloaded successfully",
        "Configuration file loaded",

        "Session created successfully",
        "Cache refreshed",
        "Email notification sent",
        "User preferences updated",
        "Health check passed",
        "Cron job completed successfully"
    ])

    elif category == "brute_force":
        return category, f"failed login for user_{user_id}"

    elif category == "suspicious_ip":
        return category, "Suspicious network activity"

    elif category == "pii_exposure":
        return category, random.choice([
            f"Aadhaar: {fake_aadhaar()}",
            f"Email: {fake_email()}",
            f"Phone: {fake_phone()}",
            f"PAN: {fake_pan()}",
        ])


while True:

    for i in range(10):

        category, message = generate_message(i)

        if category == "brute_force":
            ip = "192.168.1.50"

        elif category == "suspicious_ip":
            ip = random.choice(MALICIOUS_IPS)

        else:
            ip = f"192.168.1.{random.randint(2,254)}"

        log = {
            "source": random.choice(sources),
            "message": message,
            "ip": ip
        }

        try:
            res = requests.post(URL, json=log)
            print(f"[user_{i}] {message} | {ip} → {res.status_code}")

        except Exception as e:
            print("Error:", e)

    time.sleep(3)
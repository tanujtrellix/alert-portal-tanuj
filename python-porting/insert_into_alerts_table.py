import psycopg2
import uuid
import json

# Load the JSON data
json_data = {
    "alert": [
        {
            "explanation": {
                "malwareDetected": {
                    "malware": [
                        {
                            "name": "Exploit.Kit.URL"
                        }
                    ]
                },
                "cncServices": {
                    "cncService": [
                        {
                            "address": "77.151.106.19",
                            "channel": "GET /b/%E0%AC%8B%E0%AC%8BAAAAAAAAAAAAAAAAAAAAAAAAA HTTP/1.1::~~Accept: */*::~~Referer: http://tcpaidui.com/b/7.htm::~~Accept-Language: en-us::~~UA-CPU: x86::~~Accept-Encoding: gzip, deflate::~~User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)::~~Host: tcpaidui.com::~~Connection: Keep-Alive::~~X-Forwarded-For: 233.22.138.175::~~::~~",
                            "port": 80,
                            "protocol": "TCP"
                        }
                    ]
                },
                "osChanges": []
            },
            "src": {
                "ip": "233.22.138.175",
                "mac": "00:0c:29:cf:06:3b",
                "port": 1054
            },
            "alertUrl": "https://hainan.eng.fireeye.com/detection/objects?uuid=f83c17dd-f983-4e05-bcf7-6a56123f33fa",
            "action": "notified",
            "occurred": "2024-01-13 22:46:25 +0000",
            "attackTime": "2024-01-13 22:46:25 +0000",
            "dst": {
                "mac": "00:50:56:e8:ba:21",
                "port": 80,
                "ip": "77.151.106.19"
            },
            "applianceId": "AC1F6B19DCB0",
            "id": 3685067,
            "rootInfection": 6137088,
            "sensorIp": "172.17.56.150",
            "name": "INFECTION_MATCH",
            "severity": "MINR",
            "uuid": "f83c17dd-f983-4e05-bcf7-6a56123f33fa",
            "ack": "no",
            "product": "WEB_MPS",
            "sensor": "masala",
            "vlan": 0,
            "malicious": "yes",
            "scVersion": "1435.276"
        }
    ],
    "appliance": "CMS",
    "version": "CMS (CMS) 10.0.1.997255",
    "msg": "extended",
    "alertsCount": 1
}

# Function to generate a UUID
def generate_uuid():
    return str(uuid.uuid4())

# Function to map severity to numerical value
def map_severity(severity):
    if severity == "CRIT":
        return 5
    elif severity == "MAJR":
        return 4
    elif severity == "MINR":
        return 3
    else:
        return 2

# Function to map product to sources
def map_sources(product):
    if product == "WEB_MPS":
        return "network"
    elif product == "EMAIL_MPS":
        return "email"
    else:
        return "unknown"

# Database connection parameters
db_params = {
    'host': '10.14.39.97',
    'database': 'postgres',
    'user': 'postgres',
    'password': 'Trellix123'
}

# SQL insert statement
insert_sql = """
INSERT INTO alert (id, "tenantId", "customerId", name, message, severity, confidence, risk, "ruleId", "generatedBy", sources, attacks, "recommendedActions", "isIntelAvailable", time) 
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
"""

try:
    # Connect to the PostgreSQL database
    conn = psycopg2.connect(**db_params)
    cursor = conn.cursor()

    # Loop through each alert in the JSON data
    for alert in json_data["alert"]:
        alert_id = generate_uuid()
        name = alert["name"]
        severity = map_severity(alert["severity"])
        sources = map_sources(alert["product"])
        occurred = alert["occurred"]
        data = (
            alert_id,
            'c82ef4de-b80b-4610-81c6-261733d0d5c7',
            'hexint04sust01',
            name,
            '',  # message is kept empty
            severity,
            '2',  # confidence
            '0',  # risk
            alert["scVersion"],
            alert["product"],
            sources,
            '{*/T1102,T0000/T1103,T0001/T1103}',
            '{}',
            False,
            occurred
        )
        cursor.execute(insert_sql, data)

    # Commit the transaction
    conn.commit()

except (Exception, psycopg2.DatabaseError) as error:
    print(f"Error: {error}")
finally:
    # Close the cursor and connection
    if cursor is not None:
        cursor.close()
    if conn is not None:
        conn.close()
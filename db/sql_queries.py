# SQL queries to be executed

# SQL insert statement
INSERT_INTO_ALERT_QUERY = """
INSERT INTO alert (id, "tenantId", "customerId", name, message, severity, confidence, risk, "ruleId", "generatedBy", sources, attacks, "recommendedActions", "isIntelAvailable", time) 
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
"""

GET_FROM_NOTIFICATIONS_QUERY = """
SELECT *
FROM notifications
ORDER BY created_at DESC
LIMIT 1;
"""
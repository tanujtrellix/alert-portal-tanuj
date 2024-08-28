# SQL queries to be executed

# SQL insert statement
INSERT_INTO_ALERT_QUERY = """
INSERT INTO alert (id, "tenantId", "customerId", name, message, severity, confidence, risk, "ruleId", "generatedBy", sources, attacks, "recommendedActions", "isIntelAvailable", time) 
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
"""

INSERT_INTO_ASSET_QUERY = """
            INSERT INTO asset (id, "tenantId", "customerId", name, type, metadata, "status") 
            VALUES (%s, %s, %s, %s, %s, %s, %s);
            """

INSERT_INTO_ALERT_ASSET_QUERY = """
        INSERT INTO public.alert_asset (id, "alertId", "assetId")
        VALUES(%s, %s, %s);
        """

INSERT_INTO_OBSERVABLES_QUERY = """
        INSERT INTO alert_observables (id, alertid, category, data, createdAt)
        VALUES (%s, %s, %s, %s, %s)
        """

UPDATE_NOTIFICATIONS_PROCESSED = """
        UPDATE notifications
        SET processed = %s
        WHERE id = %s
        """

GET_FROM_NOTIFICATIONS_QUERY = """
        SELECT *
        FROM notifications
        where processed is False
        LIMIT 5;
        """


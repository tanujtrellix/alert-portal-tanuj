# import psycopg2
import uuid

from utils.logger_util import setup_logger

logger = setup_logger(__name__)

class EventParsing:

    # Function to generate a UUID
    def generate_uuid(self):
        return str(uuid.uuid4())

    # Function to map severity to numerical value
    def map_severity(self, severity):
        if severity == "CRIT":
            return 5
        elif severity == "MAJR":
            return 4
        elif severity == "MINR":
            return 3
        else:
            return 2

    # Function to map product to sources
    def map_sources(self, product):
        if product == "WEB_MPS":
            return "network"
        elif product == "EMAIL_MPS":
            return "email"
        else:
            return "unknown"

    def parse_event_for_alert(self, json_data):
        try:
            # Loop through each alert in the JSON data
            if isinstance(json_data, list):
                for alert in json_data:
                    alert_id = self.generate_uuid()
                    name = alert["name"]
                    severity = self.map_severity(alert["severity"])
                    sources = self.map_sources(alert["product"])
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
            elif isinstance(json_data, dict):
                alert = json_data
                alert_id = self.generate_uuid()
                name = alert["name"]
                severity = self.map_severity(alert["severity"])
                sources = self.map_sources(alert["product"])
                occurred = alert["occurred"]
                data = (
                    alert_id,
                    'c82ef4de-b80b-4610-81c6-261733d0d5c7',
                    'hexint04sust01-TEST',
                    name,
                    '',  # message is kept empty
                    severity,
                    '2',  # confidence
                    '0',  # risk
                    alert["sc-version"],
                    alert["product"],
                    sources,
                    '{*/T1102,T0000/T1103,T0001/T1103}',
                    '{}',
                    False,
                    occurred
                )

            else:
                return 'Not dict or list'
            return data
        except Exception as error:
            print(f"Error: {error}")


    def parse_function(self, event):
        #TO DO:logic to parse event
        return event
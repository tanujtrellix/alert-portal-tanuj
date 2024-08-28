import sys
from db import db_connection
from db import sql_queries as sql
from alert_sync import event_parsing
from decorators import event_epoch, maxmindb_geoip, decorator_manager
import json
from datetime import  datetime
from psycopg2 import extras
import uuid
from utils.collect_iocs import extract_observables, alert_description
from utils.date import date_time_current


def generate_uuid():
    return str(uuid.uuid4())

class Main:
    def __init__(self):
        # Initialize the decorator manager with the desired decorators
        self.decorator_manager = decorator_manager.DecoratorManager(
            event_epoch.EventEpoch(),
            maxmindb_geoip.MaxmindGeoIp()
        )
        self.alert_obj = event_parsing.EventParsing()
        self.db = db_connection.Db_connection()

    @property
    def parse_alert(self):
        # Define the function to be decorated
        def parsing_function(alert):
            processed_data = self.alert_obj.parse_function(alert)
            return processed_data

        # Apply decorators and return the decorated function
        decorated_add = self.decorator_manager.apply_decorators(parsing_function)
        return decorated_add
    
    def insert_alert(self, alert):
        alert_id = generate_uuid()
        name = alert["name"]
        severity = self.alert_obj.map_severity(alert["severity"].lower())
        sources = self.alert_obj.map_sources(alert["product"])
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
            alert.get("scVersion",alert.get('sc-version','NA')),
            alert["product"],
            sources,
            '{*/T1102,T0000/T1103,T0001/T1103}',
            '{}',
            False,
            occurred
        )
        self.db.execute_statement(sql.INSERT_INTO_ALERT_QUERY, data)
        return alert_id

    def insert_asset(self, alert):
        asset_id = generate_uuid()
        name = alert["name"]
        metadata = {}
        for key in alert.keys():
            if key.startswith(("src", "dst")):
                metadata[key] = alert[key]
        data = (
                asset_id,
                'c82ef4de-b80b-4610-81c6-261733d0d5c7',
                'hexint04sust01',
                name,
                'host',  
                json.dumps(metadata),
                'FAILED'
            )
        self.db.execute_statement(sql.INSERT_INTO_ASSET_QUERY, data)
        return asset_id

    def insert_into_alert_asset(self, alert_id,asset_id,):
        _id = generate_uuid()
        data = (
                _id,
                alert_id,
                asset_id
            )
        
        self.db.execute_statement(sql.INSERT_INTO_ALERT_ASSET_QUERY, data)
        return _id
    
    def insert_observables(self, alert_id, observables):
        values = []
        observables_ids = []
        for item in  observables:
            observable_id = generate_uuid()
            date_added = datetime.fromisoformat(date_time_current().replace('Z', '+00:00'))
            values.append((
                observable_id, 
                alert_id,#item['alert_id'], 
                item['category'], 
                json.dumps(item), 
                date_added
            ))
            observables_ids.append(observable_id)
        self.db.cursor.executemany(sql.INSERT_INTO_OBSERVABLES_QUERY, values)
        self.db.connection.commit()
        return observables_ids

    def update_notification_processed(self, notification_id):
        data = (True, notification_id)
        self.db.execute_statement(sql.UPDATE_NOTIFICATIONS_PROCESSED, (True, notification_id))


if __name__ == "__main__":
    main = Main()

    try:
        main.db.connect()
        notifications = main.db.execute_statement(sql.GET_FROM_NOTIFICATIONS_QUERY, fetch=True, cursor_factory=extras.DictCursor)
        for notification in notifications:
            notification_id =  notification["id"]
            print(f'Notification-ID: {notification_id}')
            notification = dict(notification)
            json_data = json.loads(notification.get('data'))
            if isinstance(json_data["alert"], list):
                alerts = json_data["alert"]
            else:
                alerts = [json_data["alert"]]
            for alert in alerts:
                decorated_alert = main.parse_alert(alert)
                alert_id = main.insert_alert(decorated_alert)
                print(f'Alert-ID: {alert_id}')
                if decorated_alert.get('src'):
                    asset_id = main.insert_asset(decorated_alert)
                    print(f'Asset-ID: {asset_id}')
                    alert_asset_id = main.insert_into_alert_asset(alert_id,asset_id)
                    print(f'Alert Asset id: {alert_asset_id}')
                data = {"id": alert_id, "alert": decorated_alert}
                observables = extract_observables(data)
                observables_ids = main.insert_observables(alert_id, observables)
                
                print('-'*40,'\n','Observables-IDs:','\n',observables_ids)
                description = alert_description(alert)
                print('-'*40,'\n','Alert Description:',description)
                main.update_notification_processed(notification_id)
                
                
    except Exception as e:
        print(e)
    finally:
        main.db.close()

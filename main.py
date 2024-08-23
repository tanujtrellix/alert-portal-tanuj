from db import db_connection
from db import sql_queries as sql
from alert_sync import event_parsing
from decorators import event_epoch, maxmindb_geoip, decorator_manager
import json, datetime


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


if __name__ == "__main__":
    main = Main()

    try:
        main.db.connect()
        a = main.db.execute_statement(sql.GET_FROM_NOTIFICATIONS_QUERY, fetch=True)
        event = json.loads(a[0][2])
        alert = event['alert']
        print(main.parse_alert(alert))
    except Exception as e:
        print(e)
    finally:
        main.db.close()

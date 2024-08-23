# Event epoch class to convert timestamp
import datetime
import pytz
import json
from functools import wraps
from utils.logger_util import setup_logger

logger = setup_logger(__name__)

# Define the EventEpoch class
class EventEpoch:
    def __init__(self):
        pass

    def __call__(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger.info(f"Executing {func.__name__} inside decorator {self.__class__.__name__}")
            alert = func(*args, **kwargs)
            logger.info(f"Decorating {func.__name__} with decorator {self.__class__.__name__}")
            result = self.decorate(alert)
            return result

        return wrapper

    def decorate(self, event):
        date_time_priority_list = ['occurred','attack-time','eventtime', 'detectedtime', 'meta_ts', 'eventtimeutc']  # Replace with actual config

        for date_time_str in date_time_priority_list:
            if date_time_str in event:
                try:
                    if date_time_str == 'eventtimeutc':
                        parsed_datetime = datetime.datetime.strptime(event[date_time_str], '%Y/%m/%d %H:%M:%S %Z%z')
                    elif date_time_str == 'occurred' or date_time_str == 'attack-time':
                        parsed_datetime = datetime.datetime.strptime(event[date_time_str], '%Y-%m-%dT%H:%M:%SZ')
                    else:
                        parsed_datetime = datetime.datetime.strptime(event[date_time_str], '%Y-%m-%dT%H:%M:%S.%fZ')
                    self.add_event_epoch(event, parsed_datetime, date_time_str)
                except ValueError:
                    logger.debug(f"Failed to parse dateTime field {date_time_str}")
        return event

    def add_event_epoch(self, event, parsed_datetime, date_time_str):
        zone = parsed_datetime.tzname()
        event[date_time_str+'_epoch'] = {
            "day": parsed_datetime.day,
            "epochtime_field": date_time_str,
            "hour": parsed_datetime.hour,
            "minute": parsed_datetime.minute,
            "month": parsed_datetime.month,
            "seconds": parsed_datetime.second,
            "timezone": zone.lower() if zone else 'utc',
            "weekday": parsed_datetime.strftime('%A').lower(),
            "year": parsed_datetime.year,
        }

# Usage
if __name__ == '__main__':
    event_epoch = EventEpoch()
    print('Testing:::::::::')

    # Read input JSON file
    with open('decorators/events.json', 'r') as input_file:
        events = json.load(input_file)

    # Process events
    for event in events:
        event_epoch.decorate(event)

    # Write output to JSON file
    with open('decorators/event_epoch_test_output.json', 'w') as output_file:
        json.dump(events, output_file, indent=4)
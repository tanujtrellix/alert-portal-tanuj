import logging
import datetime
import pytz
import json

# Define constants
EVENT_EPOCH = 'event_epoch'
EPOCHTIME_FIELD = 'epochtime_field'
HOUR = 'hour'
MINUTE = 'minute'
SECONDS = 'seconds'
DAY = 'day'
MONTH = 'month'
YEAR = 'year'
TIMEZONE = 'timezone'
WEEKDAY = 'weekday'

# Define the EventEpoch class
class EventEpoch:
    def __init__(self):
        self.id = EVENT_EPOCH

    def init(self):
        # No initialization needed in Python
        pass

    def decorate(self, event):
        date_time_priority_list = ['eventtime', 'detectedtime', 'meta_ts', 'eventtimeutc']  # Replace with actual config

        for date_time_str in date_time_priority_list:
            if date_time_str in event:
                try:
                    if date_time_str == 'eventtimeutc':
                        parsed_datetime = datetime.datetime.strptime(event[date_time_str], '%Y/%m/%d %H:%M:%S %Z%z')
                    else:
                        parsed_datetime = datetime.datetime.strptime(event[date_time_str], '%Y-%m-%dT%H:%M:%S.%fZ')
                    self.add_event_epoch(event, parsed_datetime, date_time_str)
                    break
                except ValueError:
                    logging.debug(f"Failed to parse dateTime field {date_time_str}")

    def add_event_epoch(self, event, parsed_datetime, date_time_str):
        zone = parsed_datetime.tzname()
        event[EVENT_EPOCH] = {
            EPOCHTIME_FIELD: date_time_str,
            HOUR: parsed_datetime.hour,
            MINUTE: parsed_datetime.minute,
            SECONDS: parsed_datetime.second,
            DAY: parsed_datetime.day,
            MONTH: parsed_datetime.month,
            YEAR: parsed_datetime.year,
            TIMEZONE: zone.lower() if zone else 'utc',
            WEEKDAY: parsed_datetime.strftime('%A').lower()
        }

# Usage
if __name__ == '__main__':
    event_epoch = EventEpoch()

    # Read input JSON file
    with open('event_epoch_test.json', 'r') as input_file:
        events = json.load(input_file)

    # Process events
    for event in events:
        event_epoch.decorate(event)

    # Write output to JSON file
    with open('event_epoch_test_output.json', 'w') as output_file:
        json.dump(events, output_file, indent=4)
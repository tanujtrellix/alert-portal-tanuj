import IP2Location as ip2location
import logging
import threading
import time
import json

class Geoip:
    def __init__(self):
        self.id = 1
        self.ip2location_db = None
        self.ip2location_mutex = threading.RLock()
        self.hash = ""
        self.db_file = '/Users/tanuj.maheshwari/Documents/GitHub/alert-portal/python-porting/db_files/IP2LOCATION-LITE-DB1.BIN/IP2LOCATION-LITE-DB1.BIN'

    def init(self):
        err = self.initialize_geo_ip_file()
        if err is None:
            print("IP2Location DB initialized successfully")
            self.re_init()
            self.load_events()
        else:
            print("Error initializing IP2Location DB:", err)
        return err

    def initialize_geo_ip_file(self):
        self.ip2location_mutex.acquire()
        try:
            self.ip2location_db = ip2location.IP2Location(self.db_file)
            self.hash = ""  # calculate hash here
            return None
        except Exception as e:
            logging.error("Error while initializing IP2Location DB", exc_info=True)
            self.ip2location_db = None
            self.hash = ""
            return e
        finally:
            self.ip2location_mutex.release()

    def re_init(self):
        def re_init_thread():
            while True:
                time.sleep(60)  # sleep for 1 minute
                s3_hash = ""  # calculate s3 hash here
                if s3_hash != self.hash:
                    logging.debug("Re-initializing IP2Location DB")
                    self.initialize_geo_ip_file()
                else:
                    logging.debug("Not re-initializing IP2Location DB as hash is same")

        threading.Thread(target=re_init_thread).start()

    def decorate(self, event):
        self.ip2location_mutex.acquire()
        try:
            if self.ip2location_db is None:
                logging.error("IP2Location DB is not initialized")
                return "IP2Location DB is not initialized"
            field_mappings = {
                "src": ["srccountry", "srccountrycode", "srccity", "srcdomain", "srcisp", "srcregion", "srcusagetype", "srclatitude", "srclongitude"],
                "dst": ["dstcountry", "dstcountrycode", "dstcity", "dstdomain", "dstisp", "dstregion", "dstusagetype", "dstlatitude", "dstlongitude"],
            }
            ip_versions = ["ipv4", "ipv6"]
            for field, mappings in field_mappings.items():
                for ip_version in ip_versions:
                    _field = field + ip_version
                    if ipval := event.get(_field):
                        try:
                            ip2location_record = self.ip2location_db.get_all(ipval)
                            add_fields(event, mappings, ip2location_record)
                            break
                        except Exception as e:
                            logging.error("IP2Location fetch error, ignoring decoration", exc_info=True)
        finally:
            self.ip2location_mutex.release()

    def load_events(self):
        with open('events.json') as f:
            events = json.load(f)
            for event in events:
                self.decorate(event)
                print(event)

def add_fields(event, fields, ip2location_record):
    if fields[0] not in event and ip2location_record.country_long != "-":
        event[fields[0]] = ip2location_record.country_long.lower()
    if fields[1] not in event and ip2location_record.country_short != "-":
        event[fields[1]] = ip2location_record.country_short.lower()
    if fields[2] not in event and ip2location_record.city != "-":
        event[fields[2]] = ip2location_record.city.lower()
    if fields[3] not in event and ip2location_record.domain != "-":
        event[fields[3]] = ip2location_record.domain.lower()
    if fields[4] not in event and ip2location_record.isp != "-":
        event[fields[4]] = ip2location_record.isp.lower()
    if fields[5] not in event and ip2location_record.region != "-":
        event[fields[5]] = ip2location_record.region.lower()
    if fields[6] not in event and ip2location_record.usagetype != "-":
        event[fields[6]] = ip2location_record.usagetype.lower()
    lat = ip2location_record.latitude
    long = ip2location_record.longitude
    if lat != 0 or long != 0:
        if fields[7] not in event:
            event[fields[7]] = lat
        if fields[8] not in event:
            event[fields[8]] = long

if __name__ == "__main__":
    geo_ip = Geoip()
    geo_ip.init()

# Load events from JSON file
with open('events.json') as f:
    events = json.load(f)

geo_ip.print_events(events)
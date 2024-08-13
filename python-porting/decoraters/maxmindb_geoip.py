import geoip2.database
import logging
import netaddr
import threading
import time
import json
from pprint import pprint

class MaxmindGeoIp:
    def __init__(self):
        self.id = 1
        self.geoip2_city_reader = None
        self.geoip2_country_reader = None
        self.geoip2_asn_reader = None
        self.geoip2_mutex = threading.RLock()
        self.db_files = {
            'city': '/Users/tanuj.maheshwari/Documents/GitHub/alert-portal/python-porting/db_files/GeoLite2-City.mmdb',
            'country': '/Users/tanuj.maheshwari/Documents/GitHub/alert-portal/python-porting/db_files/GeoLite2-Country.mmdb',
            'asn': '/Users/tanuj.maheshwari/Documents/GitHub/alert-portal/python-porting/db_files/GeoLite2-ASN.mmdb'
        }

    def init(self):
        err = self.initialize_maxmind_geo_ip_files()
        if err is None:
            print("GeoIP2 readers initialized successfully")
        else:
            print("Error initializing GeoIP2 readers:", err)
        return err

    def initialize_maxmind_geo_ip_files(self):
        self.geoip2_mutex.acquire()
        try:
            self.geoip2_city_reader = geoip2.database.Reader(self.db_files['city'])
            self.geoip2_country_reader = geoip2.database.Reader(self.db_files['country'])
            self.geoip2_asn_reader = geoip2.database.Reader(self.db_files['asn'])
            return None
        except Exception as e:
            logging.error("Error while initializing MaxmindGeoIP", exc_info=True)
            return e
        finally:
            self.geoip2_mutex.release()

    def decorate(self, event):
        self.geoip2_mutex.acquire()
        try:
            if self.geoip2_city_reader is None or self.geoip2_country_reader is None or self.geoip2_asn_reader is None:
                logging.error("GeoIP2 readers are not initialized")
                return "GeoIP2 readers are not initialized"
            for field in ["src", "dst"]:
                _field = field + "ipv4"
                if ipval := event.get(_field):
                    ip = netaddr.IPAddress(ipval)
                    if ip.version != 4:
                        continue
                    try:
                        city_response = self.geoip2_city_reader.city(ipval)
                        country_response = self.geoip2_country_reader.country(ipval)
                        asn_response = self.geoip2_asn_reader.asn(ipval)
                        if field + "city" not in event:
                            if city_response.city.name:
                                event[field + "city"] = city_response.city.name.lower()
                            else:
                                logging.warning(f"City not found for IP {ipval} in GeoLite2-City.mmdb")
                        if field + "country" not in event:
                            if country_response.country.name:
                                event[field + "country"] = country_response.country.name.lower()
                            else:
                                logging.warning(f"Country not found for IP {ipval} in GeoLite2-Country.mmdb")
                        if field + "countrycode" not in event:
                            if country_response.country.iso_code:
                                event[field + "countrycode"] = country_response.country.iso_code.lower()
                            else:
                                logging.warning(f"Country code not found for IP {ipval} in GeoLite2-Country.mmdb")
                        if field + "domain" not in event:
                            if country_response.traits.domain:
                                event[field + "domain"] = country_response.traits.domain.lower()
                            else:
                                logging.warning(f"Domain not found for IP {ipval} in GeoLite2-Country.mmdb")
                        if field + "isp" not in event:
                            if asn_response.autonomous_system_organization:
                                event[field + "isp"] = asn_response.autonomous_system_organization.lower()
                            else:
                                logging.warning(f"ISP not found for IP {ipval} in GeoLite2-ASN.mmdb")
                        if field + "region" not in event:
                            if city_response.subdivisions.most_specific.name:
                                event[field + "region"] = city_response.subdivisions.most_specific.name.lower()
                            else:
                                logging.warning(f"Region not found for IP {ipval} in GeoLite2-City.mmdb")
                        if field + "usagetype" not in event:
                            if country_response.traits.user_type:
                                event[field + "usagetype"] = country_response.traits.user_type.lower()
                            else:
                                logging.warning(f"Usage type not found for IP {ipval} in GeoLite2-Country.mmdb")
                        if field + "latitude" not in event:
                            if city_response.location.latitude:
                                event[field + "latitude"] = city_response.location.latitude
                            else:
                                logging.warning(f"Latitude not found for IP {ipval} in GeoLite2-City.mmdb")
                        if field + "longitude" not in event:
                            if city_response.location.longitude:
                                event[field + "longitude"] = city_response.location.longitude
                            else:
                                logging.warning(f"Longitude not found for IP {ipval} in GeoLite2-City.mmdb")
                        if field + "asn" not in event:
                            if asn_response.autonomous_system_number:
                                event[field + "asn"] = asn_response.autonomous_system_number
                            else:
                                logging.warning(f"ASN not found for IP {ipval} in GeoLite2-ASN.mmdb")
                    except geoip2.errors.AddressNotFoundError:
                        logging.error(f"GeoIP2 Address not found error for IP {ipval}, ignoring decoration")
                    except Exception as e:
                        logging.error(f"GeoIP2 fetch error for IP {ipval}, ignoring decoration", exc_info=True)
        finally:
            self.geoip2_mutex.release()

    def get_id(self):
        return self.id

    def print_events(self, events):
        for event in events:
            self.decorate(event)
            pprint(event)
            with open("procssed_events.json", 'w') as processed_json:
                json.dump([event], processed_json)

# Example usage:
maxmind_geo_ip = MaxmindGeoIp()
maxmind_geo_ip.init()

# Load events from JSON file
with open('events.json') as f:
    events = json.load(f)

maxmind_geo_ip.print_events(events)
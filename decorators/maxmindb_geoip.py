import geoip2.database
import netaddr
import threading
import json
from functools import wraps
from utils.logger_util import setup_logger

logger = setup_logger(__name__)

class MaxmindGeoIp:
    def __init__(self):
        self.id = 1
        self.geoip2_city_reader = None
        self.geoip2_country_reader = None
        self.geoip2_asn_reader = None
        self.geoip2_mutex = threading.RLock()
        self.db_files = {
            'city': 'decorators/maxmindb_geoip_db_files/GeoLite2-City.mmdb',
            'country': 'decorators/maxmindb_geoip_db_files//GeoLite2-Country.mmdb',
            'asn': 'decorators/maxmindb_geoip_db_files//GeoLite2-ASN.mmdb'
        }
        self.initialize_maxmind_geo_ip_files()

    def __call__(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger.info(f"Executing {func.__name__} inside decorator {self.__class__.__name__} ")
            alert = func(*args, **kwargs)
            logger.info(f"Decorating {func.__name__} with decorator {self.__class__.__name__} ")
            result = self.decorate(alert)
            return result

        return wrapper

    def initialize_maxmind_geo_ip_files(self):
        self.geoip2_mutex.acquire()
        try:
            self.geoip2_city_reader = geoip2.database.Reader(self.db_files['city'])
            self.geoip2_country_reader = geoip2.database.Reader(self.db_files['country'])
            self.geoip2_asn_reader = geoip2.database.Reader(self.db_files['asn'])
            return None
        except Exception as e:
            logger.error("Error while initializing MaxmindGeoIP", exc_info=True)
            return e
        finally:
            self.geoip2_mutex.release()

    def decorate(self, event):
        self.geoip2_mutex.acquire()
        try:
            if self.geoip2_city_reader is None or self.geoip2_country_reader is None or self.geoip2_asn_reader is None:
                logger.error("GeoIP2 readers are not initialized")
                return "GeoIP2 readers are not initialized"
            for field in ["src", "dst"]:
                _field = field + "ipv4"
                if ipval := event.get(_field) or event.get(field).get('ip'):
                    ip = netaddr.IPAddress(ipval)
                    if ip.version != 4:
                        continue
                    try:
                        try:
                            city_response = self.geoip2_city_reader.city(ipval)
                            if field + "city" not in event:
                                if city_response.city.name:
                                    event[field + "city"] = city_response.city.name.lower()
                                else:
                                    logger.warning(f"City not found for IP {ipval} in GeoLite2-City.mmdb")
                                    event[field + "city"] = ''
                            if field + "region" not in event:
                                if city_response.subdivisions.most_specific.name:
                                    event[field + "region"] = city_response.subdivisions.most_specific.name.lower()
                                else:
                                    logger.warning(f"Region not found for IP {ipval} in GeoLite2-City.mmdb")
                                    event[field + "region"] = ''
                            if field + "latitude" not in event:
                                if city_response.location.latitude:
                                    event[field + "latitude"] = city_response.location.latitude
                                else:
                                    logger.warning(f"Latitude not found for IP {ipval} in GeoLite2-City.mmdb")
                                    event[field + "latitude"] = ''
                            if field + "longitude" not in event:
                                if city_response.location.longitude:
                                    event[field + "longitude"] = city_response.location.longitude
                                else:
                                    logger.warning(f"Longitude not found for IP {ipval} in GeoLite2-City.mmdb")
                                    event[field + "longitude"] = ''
                        except geoip2.errors.AddressNotFoundError:
                            logger.error(f"GeoIP2 Address not found error for IP {ipval}, ignoring decoration")
                            event[field + "city"], event[field + "region"], event[field + "latitude"], event[field + "longitude"] = '', '', '', ''
                            pass
                        try:
                            country_response = self.geoip2_country_reader.country(ipval)
                            if field + "country" not in event:
                                if country_response.country.name:
                                    event[field + "country"] = country_response.country.name.lower()
                                else:
                                    logger.warning(f"Country not found for IP {ipval} in GeoLite2-Country.mmdb")
                                    event[field + "country"] = ''
                            if field + "countrycode" not in event:
                                if country_response.country.iso_code:
                                    event[field + "countrycode"] = country_response.country.iso_code.lower()
                                else:
                                    logger.warning(f"Country code not found for IP {ipval} in GeoLite2-Country.mmdb")
                                    event[field + "countrycode"] = ''
                            if field + "domain" not in event:
                                if country_response.traits.domain:
                                    event[field + "domain"] = country_response.traits.domain.lower()
                                else:
                                    logger.warning(f"Domain not found for IP {ipval} in GeoLite2-Country.mmdb")
                                    event[field + "domain"] = ''
                            if field + "usagetype" not in event:
                                if country_response.traits.user_type:
                                    event[field + "usagetype"] = country_response.traits.user_type.lower()
                                else:
                                    logger.warning(f"Usage type not found for IP {ipval} in GeoLite2-Country.mmdb")
                                    event[field + "usagetype"] = ''
                        except geoip2.errors.AddressNotFoundError:
                            logger.error(f"GeoIP2 Address not found error for IP {ipval}, ignoring decoration")
                            event[field + "country"], event[field + "countrycode"], event[field + "domain"], event[field + "usagetype"] = '', '', '', ''
                            pass

                        try:
                            asn_response = self.geoip2_asn_reader.asn(ipval)
                            if field + "isp" not in event:
                                if asn_response.autonomous_system_organization:
                                    event[field + "isp"] = asn_response.autonomous_system_organization.lower()
                                else:
                                    logger.warning(f"ISP not found for IP {ipval} in GeoLite2-ASN.mmdb")
                                    event[field + "isp"] = ''
                            if field + "asn" not in event:
                                if asn_response.autonomous_system_number:
                                    event[field + "asn"] = asn_response.autonomous_system_number
                                else:
                                    logger.warning(f"ASN not found for IP {ipval} in GeoLite2-ASN.mmdb")
                                    event[field + "asn"] = ''
                        except geoip2.errors.AddressNotFoundError:
                            logger.error(f"GeoIP2 Address not found error for IP {ipval}, ignoring decoration")
                            event[field + "isp"], event[field + "asn"] = '', ''
                            pass
                    except Exception as e:
                        logger.error(f"GeoIP2 fetch error for IP {ipval}, ignoring decoration", exc_info=True)
        finally:
            self.geoip2_mutex.release()
            return event

    def get_id(self):
        return self.id

    def print_events(self, events):
        for event in events:
            self.decorate(event)
            with open("decorators/procssed_events.json", 'w') as processed_json:
                json.dump([event], processed_json)

# Example usage:
# maxmind_geo_ip = MaxmindGeoIp()
# maxmind_geo_ip.init()
#
# # Load events from JSON file
# with open('decorators/events.json') as f:
#     events = json.load(f)
#
# maxmind_geo_ip.print_events(events)
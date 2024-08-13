import os
import re

# Constants
EQUAL = "equal"
HASANYONEEQUAL = "hasAnyOneEqual"
NOT_EQUAL = "notEqual"
HAS_ALL = "hasAll"
ALL_MISSING = "allMissing"
SUBSTRING = "substring"
STARTSWITH = "startsWith"
ENDSWITH = "endsWith"
REGEX = "regex"

# Compile the regex for MITRE ID
MITRE_ID_REGEX = re.compile(r"(t|T)[0-9]{4}(.[0-9]{3})?")  # regex for mitre_id

# Additional constants
CLASS_FIELD = "class"
UNKNOWN = "unknown"
META_RULE = "meta_rule"
META_CLASS = "metaclass"
EVENTID = "_eventid"
METADATA = "__metadata__"
DYNAMIC_TAXONOMY = "dynamic_taxonomy"

def get_json_parsing_dir():
    """ Get the JSON parsing directory from the environment variable or default to the current directory. """
    json_parsing_dir = os.getenv("JSONPARSING_DIR")
    if not json_parsing_dir:
        print("Environment variable not set, trying using current working directory")
        json_parsing_dir = os.getcwd() + "/jsonparsing"
    return json_parsing_dir

JSONMAPPER_DIR = get_json_parsing_dir()

def malware_detected_map():
    """ Return a mapping of malware detection fields. """
    return {
        "rule": "stype",
        "virus": "name",
        "md5": "md5sum",
        "sha256": "sha256",
        "url": "url",
        "attackinfo": "http-header",
        "threat": "threat_type",
    }

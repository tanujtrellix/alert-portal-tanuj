import json
import os
import re
import string
from typing import Any, Dict, List, Optional, Union
import ipaddress

import constants  # Assuming the constants are defined in a constants.py module

def is_map_and_empty(v: Any) -> bool:
    """ Check if a given value is an empty dictionary. """
    return isinstance(v, dict) and len(v) == 0

def is_object(val: Any) -> bool:
    """ Check if the value is a dictionary. """
    return val is not None and isinstance(val, dict)

def is_object_or_array(val: Any) -> int:
    """ Check if the value is a dictionary or list. """
    if isinstance(val, dict):
        return 1
    elif isinstance(val, list):
        return 2
    return 0

def ip4_or_6(address: str) -> int:
    """ Determine if the IP address is IPv4, IPv6 or invalid. """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return 0

    if isinstance(ip, ipaddress.IPv4Address):
        return 4
    elif isinstance(ip, ipaddress.IPv6Address):
        return 6
    return 0

def v4(key: str) -> bool:
    """ Check if the key is IPv4. """
    return ip4_or_6(key) == 4

def v6(key: str) -> bool:
    """ Check if the key is IPv6. """
    return ip4_or_6(key) == 6

def get_string_formatted_value(value: Any) -> str:
    """ Convert various types to a formatted string. """
    if isinstance(value, dict):
        return ','.join(get_string_formatted_value(v) for v in value.values())
    elif isinstance(value, list):
        return ','.join(get_string_formatted_value(v) for v in value)
    elif isinstance(value, float):
        return f"{value:.2f}".rstrip('0').rstrip('.')
    return str(value)

def has(m: dict, key: str) -> bool:
    """ Check if the dictionary has a specific key. """
    return m is not None and key in m

def contains(val: str, keys: List[str]) -> bool:
    """ Check if a value exists in a list of keys. """
    return val in keys

def evaluate_regex(regex: str, value: str) -> Tuple[bool, Optional[Exception]]:
    """ Evaluate if the value matches the regex. """
    try:
        r = re.compile(regex)
        return r.match(value) is not None, None
    except re.error as regex_err:
        print("Error regex error")
        return False, regex_err

def deep_copy_map(src: Dict[str, Any], dst: Dict[str, Any]) -> None:
    """ Deep copy one map to another using JSON serialization. """
    if src is None:
        raise ValueError("src cannot be nil")
    if dst is None:
        raise ValueError("dst cannot be nil")
    
    dst.clear()
    dst.update(json.loads(json.dumps(src)))

class CefLeefMeta:
    def __init__(self, class_name: str, metaclass: str, custom_url: List[str], rule: 'Rule'):
        self.class_name = class_name
        self.metaclass = metaclass
        self.custom_url = custom_url
        self.rule = rule

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__)

class Rule:
    def __init__(self, equal: Dict[str, List[str]], has_any_one_equal: Dict[str, List[str]], 
                 not_equal: Dict[str, List[str]], has_all: List[str], 
                 all_missing: List[str], substring: Dict[str, List[str]], 
                 starts_with: Dict[str, List[str]], ends_with: Dict[str, List[str]], 
                 regex: Dict[str, List[str]]):
        self.equal = equal
        self.has_any_one_equal = has_any_one_equal
        self.not_equal = not_equal
        self.has_all = has_all
        self.all_missing = all_missing
        self.substring = substring
        self.starts_with = starts_with
        self.ends_with = ends_with
        self.regex = regex

    def __str__(self):
        return (f"equal {self.equal}, "
                f"hasAnyOneEqual {self.has_any_one_equal}, "
                f"notEqual {self.not_equal}, "
                f"hasAll {self.has_all}, "
                f"allMissing {self.all_missing}, "
                f"substring {self.substring}, "
                f"startsWith {self.starts_with}, "
                f"endsWith {self.ends_with}, "
                f"regex {self.regex}")

def populate_cef_leef_config(path: str) -> List[CefLeefMeta]:
    """ Populate the CEF/LEEF configuration from a JSON file. """
    with open(path, 'r') as json_file:
        byte_value = json_file.read()
        all_config = json.loads(byte_value)
        return [CefLeefMeta(**config) for config in all_config]

def populate_cef_leef_mappings(path: str, all_config: List[CefLeefMeta], mappers: Dict[str, Dict[str, Any]], prefix: str) -> None:
    """ Populate mappings from files based on CEF/LEEF configurations. """
    for config in all_config:
        mappings = get_mappings_from_file(f"{path}/{prefix}{config.class_name}.json")
        mappers[config.class_name] = mappings

def convert_custom_labels_cef_leef(event: Dict[str, Any]) -> None:
    """ Convert custom labels in CEF/LEEF events. """
    for key, new_label in event.items():
        if not key.lower().endswith("label"):
            continue
        key_without_label = key[:-5]
        new_val = event.get(key_without_label)

        # Delete custom labels if there is no relevant custom variable
        event.pop(key, None)
        event.pop(key_without_label, None)

        if isinstance(new_label, str) and new_val is not None:
            event[new_label] = new_val

def split_cef_leef_urls(custom_url_fields: List[str], event: Dict[str, Any]) -> None:
    """ Split URLs into protocol, domain, and URI components. """
    for val in custom_url_fields:
        if isinstance(event.get(val), str):
            url_value = event[val]
            index0 = url_value.find("://")
            if index0 != -1:
                event["protocol"] = url_value[:index0]
                url_value = url_value[index0 + 3:]
                del event[val]
            index_of_slash = url_value.find("/")
            if index_of_slash != -1:
                event["domain"] = url_value[:index_of_slash]
                event["uri"] = url_value[index_of_slash:]
                del event[val]

def get_mappings_from_file(path: str) -> Dict[str, Any]:
    """ Read mappings from a JSON file. """
    with open(path, 'r') as json_file:
        byte_value = json_file.read()
        return json.loads(byte_value)

def string_compare(func_type: str, source_string: str, param: str) -> bool:
    """ Compare strings based on specified comparison function. """
    source_string = source_string.lower()
    param = param.lower()

    if func_type == constants.SUBSTRING:
        return param in source_string
    elif func_type == constants.ENDSWITH:
        return source_string.endswith(param)
    elif func_type == constants.STARTSWITH:
        return source_string.startswith(param)
    elif func_type == constants.EQUAL:
        return source_string == param
    elif func_type == constants.HASANYONEEQUAL:
        return source_string == param
    elif func_type == constants.NOT_EQUAL:
        return source_string != param
    elif func_type == constants.Regex:
        current_match, _ = evaluate_regex(param, source_string)
        return current_match
    else:
        print("Operation not supported")
        return False

def evaluate_map_of_sub_rules(map_of_sub_rules: Dict[str, List[str]], event: Dict[str, Any], func_type: str) -> bool:
    """ Evaluate sub-rules in the event against a set of conditions. """
    result = True
    for sub_rule_field, sub_rule_value_arr in map_of_sub_rules.items():
        event_field_val = str(event.get(sub_rule_field, ""))
        any_one_matched = any(string_compare(func_type, event_field_val, sub_rule_value) for sub_rule_value in sub_rule_value_arr)
        result = result and any_one_matched

        if not result:
            break
    return result

def evaluate_has_or_missing_rules(arr_of_sub_rules: List[str], event: Dict[str, Any], func_type: str) -> bool:
    """ Evaluate if all or none of the specified keys exist in the event. """
    result = True
    for r_value_arr_field in arr_of_sub_rules:
        exists = r_value_arr_field in event
        if func_type == constants.HAS_ALL:
            result = result and exists
        elif func_type == constants.ALL_MISSING:
            result = result and not exists
        else:
            print("Operation not supported")
            return False
        if not result:
            break
    return result

def evaluate_has_any_one_equal(map_of_sub_rules: Dict[str, List[str]], event: Dict[str, Any], func_type: str) -> bool:
    """ Evaluate if any of the keys in the map have at least one matching value. """
    if not map_of_sub_rules:
        return True
    result = False
    for sub_rule_field, sub_rule_value_arr in map_of_sub_rules.items():
        event_field_val = str(event.get(sub_rule_field, ""))
        any_one_matched = any(string_compare(func_type, event_field_val, sub_rule_value) for sub_rule_value in sub_rule_value_arr)
        result = result or any_one_matched
    return result

def evaluate_generic_rule(rule: Rule, event: Dict[str, Any]) -> bool:
    """ Evaluate a generic rule against the event. """
    has_all = evaluate_has_or_missing_rules(rule.has_all, event, constants.HAS_ALL)
    has_any_one_equal = evaluate_has_any_one_equal(rule.has_any_one_equal, event, constants.HASANYONEEQUAL)
    all_missing = evaluate_has_or_missing_rules(rule.all_missing, event, constants.ALL_MISSING)
    substring = evaluate_map_of_sub_rules(rule.substring, event, constants.SUBSTRING)
    startswith = evaluate_map_of_sub_rules(rule.starts_with, event, constants.STARTSWITH)
    endswith = evaluate_map_of_sub_rules(rule.ends_with, event, constants.ENDSWITH)
    regex = evaluate_map_of_sub_rules(rule.regex, event, constants.Regex)
    equal = evaluate_map_of_sub_rules(rule.equal, event, constants.EQUAL)
    not_equal = evaluate_map_of_sub_rules(rule.not_equal, event, constants.NOT_EQUAL)
    
    # All parts of the rule should evaluate to True
    return (has_all and equal and not_equal and regex and
            substring and startswith and endswith and all_missing and has_any_one_equal)

def is_array(m: Dict[str, Any], key: str) -> bool:
    """ Check if the value in the map is an array. """
    return isinstance(m.get(key), list)

def string_value(v: Any) -> str:
    """ Get string value from the provided value, if possible. """
    if isinstance(v, str):
        return v
    return ""

def map_elements(elements: List[Any], key: str) -> List[Any]:
    """ Map elements of a list of dictionaries based on a specified key. """
    all_values = []
    for each in elements:
        if isinstance(each, dict) and key in each:
            if key == "url":
                all_values.append(defang_url(str(each[key])))
            else:
                all_values.append(each[key])
    return all_values

def defang_url(url: str) -> str:
    """ Defang a URL by replacing 'http' with 'hxxp'. """
    url = url.replace("http", "hxxp", 1)
    if len(url) > 4 and url[:4] != "hxxp":
        url = "hxxp://" + url
    else:
        url = "hxxp://" + url
    return url.replace(":", "[:]", 1)

def parse_mitre_id(description: str) -> List[str]:
    """ Parse MITRE IDs from the description field. """
    idx = description.rfind(":") + 1
    desc = description[idx:]
    ids = constants.MITRE_ID_REGEX.findall(desc)
    return ids

def stringify_value_in_map(old_key: str, new_key: str, data: Dict[str, Any], should_delete: bool) -> None:
    """ Convert the value in the map to a string under a new key. """
    _data = data.get(old_key)
    if _data is None:
        return
    data[new_key] = json.dumps(_data)
    if should_delete:
        del data[old_key]

import uuid
from utils.ioc import ioc_extract, ioc_defang
import json
from logging import Logger
import logging
LOGGER = logging.getLogger()


# -----------------------------------------------------------------------------
# Extract Observables
# -----------------------------------------------------------------------------
def extract_observables(data):
    """Collect Observables"""

    try:
        potential_iocs = {}
        potential_iocs["explanation"] = data["alert"]["explanation"]

        # Don't process os-changes since it's massive
        if "os-changes" in potential_iocs["explanation"]:
            del potential_iocs["explanation"]["os-changes"]

        if "src" in data["alert"]:
            potential_iocs["src"] = data["alert"]["src"]
        if "dest" in data["alert"]:
            potential_iocs["dest"] = data["alert"]["dest"]

        iocs = ioc_extract(json.dumps(potential_iocs))
        observables = []
        for ioc in iocs:
            if "attack" not in ioc:
                for item in iocs[ioc]:
                    observable = {
                        # "alert_id":data['id'],
                        "category":ioc,
                        "category_friendly" : ioc.replace("_", " "),
                        "data_fanged" :item,
                        "data_defanged" : ioc_defang(item),
                        # "date_added" :date_time_current()
                    }
                    observables.append(observable)
        # print(json.dumps(observables, indent=4))
        return observables
        # print("Observables exctracted.", data)
    except Exception as error:  # pylint: disable=broad-except
        message = f"Exception during observable extraction: {error}"
        LOGGER.exception(message, exc_info=True)


    # -----------------------------------------------------------------------------
    # Malware Description
    # -----------------------------------------------------------------------------
def malware_description(malware, description):
    """Malware Description"""
    if isinstance(malware, list):
        for item in malware:
            description = malware_description(item, description)

    if "name" in malware:
        if len(description) == 0:
            description = malware["name"]
        else:
            description += ", " + malware["name"]

    return description



# -----------------------------------------------------------------------------
    # Alert Description
    # -----------------------------------------------------------------------------
def alert_description(alert):
    """Alert description"""
    description = ""

    # Smartvision
    if alert["name"] == "smartvision-event":
        if "description" in alert:
            description = alert["description"]

    # IPS
    if alert["name"] == "ips-event":
        if "ips-detected" in alert["explanation"]:
            if "sig-name" in alert["explanation"]["ips-detected"]:
                description += alert["explanation"]["ips-detected"]["sig-name"]

    # Standard
    if "malware-detected" in alert["explanation"]:
        for malware in alert["explanation"]["malware-detected"]:
            description += malware_description(
                alert["explanation"]["malware-detected"][malware],
                description,
            )

    return description


# -----------------------------------------------------------------------------
# Generate Pivot URLs
# -----------------------------------------------------------------------------
def _pivot_url(
    self, investigation, asset_category, asset_url, alert
):  # pylint:disable=too-many-branches
    """Pivot URL"""

    pivot_url = asset_url
    # Define alert properties
    if investigation["type"] == "network":
        if asset_category in ["NX"]:
            if "class" in alert:
                if alert["class"] == "SmartVision":
                    pivot_url += f'/notification_url?uuid={alert["uuid"]}'
                if alert["class"] == "IPS":
                    pivot_url += f'/notification_url/ips_events?ev_id={alert["id"]}'
                if alert["class"] == "RISKWARE":
                    pivot_url += f'/detection/objects?uuid={alert["uuid"]}'
            elif "name" in alert:
                if alert["name"] in [
                    "domain-match",
                    "infection-match",
                    "web-infection",
                    "malware-object",
                    "malware-callback",
                ]:
                    pivot_url += f'/event_stream/events_for_bot?ev_id={alert["id"]}'

        elif asset_category in ["IA", "PX"]:
            if asset_category == "PX":
                bpf = ""

                if "src" in alert and "ip" in alert["src"]:
                    bpf += f'src%20host%20{alert["src"]["ip"]}'
                if "dst" in alert and "ip" in alert["dst"]:
                    if bpf != "":
                        bpf += "%20and%20"
                    bpf += f'dst%20host%20{alert["dst"]["ip"]}'

                if "attack-time" in alert:
                    alert_time = alert["attack-time"]
                elif "occurred" in alert:
                    alert_time = alert["occurred"]

                stime = int(date_time_to_timestamp(alert_time)) - 300
                etime = int(date_time_to_timestamp(alert_time)) + 900

                pivot_url += (
                    f"/i/searches.html?bpf={bpf}&stime={stime}&etime={etime}&window=1200"
                )

            if asset_category == "IA":
                search = "?"
                if "src" in alert and "ip" in alert["src"]:
                    search += f'sourceIpV4Address={alert["src"]["ip"]}'
                if "dst" in alert and "ip" in alert["dst"]:
                    if search != "?":
                        search += "&operator=AND&"
                    search += f'destinationIpV4Address={alert["dst"]["ip"]}'

                if "attack-time" in alert:
                    alert_time = alert["attack-time"]
                elif "occurred" in alert:
                    alert_time = alert["occurred"]

                start = date_time_subtract(alert_time, "seconds", 300).replace("+00:00", "Z")
                end = date_time_add(alert_time, "seconds", 900).replace("+00:00", "Z")
                date_format = "YYYY-MM-DDTHH:ss:mmZ"

                date = f"{start}%20TO%20{end}%20FORMAT%20{date_format}"
                pivot_url += f"{search}&date={date}"

    return pivot_url

import datetime
import dateutil.parser
from dateutil.relativedelta import relativedelta


# -----------------------------------------------------------------------------
# Get current UTC Date Time String
# -----------------------------------------------------------------------------
def date_time_current(microseconds=False):
    """Get current UTC date & time.

    Args:
        microseconds (bool): Include microseconds in date output

    Returns:
        string: UTC Date & Time

    Example:
        >>> from utils.date import date_time_current
        >>>
        >>> date_time_current()
        2021-04-09T15:28:30Z
    """
    string_format = "%Y-%m-%dT%H:%M:%S"

    if microseconds:
        string_format = string_format + ",%f"

    # RFC3339
    string_format = string_format + "Z"

    return datetime.datetime.now(datetime.timezone.utc).strftime(string_format)
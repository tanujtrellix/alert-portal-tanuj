# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
# Installed
import logging
from ioc_finder import find_iocs
from ioc_fanger import fang as fang, defang

# Utils
# from utils.logger import logger_default

# -----------------------------------------------------------------------------
# Logger
# -----------------------------------------------------------------------------
# LOGGER = logger_default()
LOGGER = logging.getLogger()

# -----------------------------------------------------------------------------
# Extract
# -----------------------------------------------------------------------------
def ioc_extract(data):
    """Extract IOC from string

    Args:
        data (string): String to extract IOCs from

    Returns:
        dict: IOCs

    Example:
        >>> from utils.ioc import ioc_extract
        >>>
        >>> text = "This is just an foobar.com https://example.org/test/bingo.php"
        >>> iocs = ioc_extract(text)
        >>> print(iocs['domains'])
        ['foobar.com', 'example.org']
        >>> print(iocs['urls'])
        ['https://example.org/test/bingo.php']
    """
    return find_iocs(data)


# -----------------------------------------------------------------------------
# Defang
# -----------------------------------------------------------------------------
def ioc_defang(data):
    """Defang a fanged IOC string

    Args:
        data (string): String to defang.

    Returns:
        string: Defanged string

    Example:
        >>> from utils.ioc import ioc_defang
        >>>
        >>> ioc_defang("http://bad.com/phishing.php")
        hXXp://bad[.]com/phishing[.]php
    """
    return defang(data)


# -----------------------------------------------------------------------------
# Fang
# -----------------------------------------------------------------------------
def ioc_fang(data):
    """Fang a defanged IOC string

    Args:
        data (string): String to fang.

    Returns:
        string: Fanged string

    Example:
        >>> from utils.ioc import ioc_fang
        >>>
        >>> ioc_fang("hXXp://bad[.]com/phishing[.]php")
        http://bad.com/phishing.php
    """
    return fang(data)

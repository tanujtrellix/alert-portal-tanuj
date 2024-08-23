# utils/logger_util.py

import logging


def setup_logger(name):
    """
    Sets up a logger with a specified name and returns it.
    """
    # Create a logger
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Create handlers
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # Create formatters and add them to handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)

    # Add handlers to the logger
    if not logger.hasHandlers():
        logger.addHandler(ch)

    return logger

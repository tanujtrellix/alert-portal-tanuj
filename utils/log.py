# utils/logger_util.py

# import logging
#
#
# def setup_logger(name):
#     """
#     Sets up a logger with a specified name and returns it.
#     """
#     # Create a logger
#     logger = logging.getLogger(name)
#     logger.setLevel(logging.DEBUG)
#
#     # Create handlers
#     ch = logging.StreamHandler()
#     ch.setLevel(logging.DEBUG)
#
#     # Create formatters and add them to handlers
#     formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#     ch.setFormatter(formatter)
#
#     # Add handlers to the logger
#     if not logger.hasHandlers():
#         logger.addHandler(ch)
#
#     return logger


## new code for logging as per sa.py
#import logging
import logging.handlers, os


class FELogger():
    def __init__(self, prefix):
        self.prefix = prefix
        self.logger = logging.getLogger(prefix + 'Logger')
        # handler = logging.handlers.SysLogHandler(address='/dev/log')
        # self.logger.addHandler(handler)
        # self.logger.setLevel(logging.INFO)
        self.pid = str(os.getpid())
        self.enable_verbose_logs = False

    def SetPrefix(self, prefix):
        self.prefix = prefix

    def SetVerbose(self, verbose):
        self.enable_verbose_logs = verbose

    def LogDebug(self, message, logPrefix=None):
        if not logPrefix:
            output = '{}[{}]: [{}.DEBUG]: {}'.format(self.prefix, self.pid,
                                                     self.prefix, message)
        else:
            output = '{}[{}]: [{}.DEBUG]: {} {}'.format(
                self.prefix, self.pid, self.prefix, logPrefix, message)
        self.logger.debug(output)

        if self.enable_verbose_logs == True:
            self.logger.info(output)

        # FOR DEV
        print(message)


    def LogInfo(self, message, logPrefix=None):
        if not logPrefix:
            output = '{}[{}]: [{}.INFO]: {}'.format(self.prefix, self.pid,
                                                    self.prefix, message)
        else:
            output = '{}[{}]: [{}.INFO]: {} {}'.format(self.prefix, self.pid,
                                                       self.prefix, logPrefix,
                                                       message)
        self.logger.info(output)

    def LogCritical(self, message, logPrefix=None):
        if not logPrefix:
            output = '{}[{}]: [{}.CRITICAL]: {}'.format(
                self.prefix, self.pid, self.prefix, message)
        else:
            output = '{}[{}]: [{}.CRITICAL]: {} {}'.format(
                self.prefix, self.pid, self.prefix, logPrefix, message)
        self.logger.critical(output)

    def LogError(self, message, logPrefix=None):
        if not logPrefix:
            output = '{}[{}]: [{}.ERR]: {}'.format(self.prefix, self.pid,
                                                   self.prefix, message)
        else:
            output = '{}[{}]: [{}.ERR]: {} {}'.format(self.prefix, self.pid,
                                                      self.prefix, logPrefix,
                                                      message)
        self.logger.error(output)

    def LogWarning(self, message, logPrefix=None):
        if not logPrefix:
            output = '{}[{}]: [{}.WARNING]: {}'.format(self.prefix, self.pid,
                                                       self.prefix, message)
        else:
            output = '{}[{}]: [{}.WARNING]: {} {}'.format(
                self.prefix, self.pid, self.prefix, logPrefix, message)
        self.logger.warning(output)


sharedlog = FELogger('python')


def InitSharedLogger(prefix):
    sharedlog.SetPrefix(prefix)


def SetVerbose(verbose):
    sharedlog.SetVerbose(verbose)


def LogDebug(message):
    sharedlog.LogDebug(message)


def LogInfo(message):
    sharedlog.LogInfo(message)


def LogCritical(message):
    sharedlog.LogCritical(message)


def LogError(message):
    sharedlog.LogError(message)


def LogWarning(message):
    sharedlog.LogWarning(message)


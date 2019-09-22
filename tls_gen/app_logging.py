import sys
import os
import shutil
import logging

def create_logger():
    # create logger for "Sample App"
    logger = logging.getLogger('app')
    logger.setLevel(logging.DEBUG)

    # create file handler which logs even debug messages
    fh = logging.FileHandler('application.log', mode='w')
    fh.setLevel(logging.DEBUG)

    # create console handler with a higher log level
    ch = logging.StreamHandler(stream=sys.stdout)
    ch.setLevel(logging.INFO)

    # create formatter and add it to the handlers
    formatterFile = logging.Formatter(#'%(asctime)s %(levelname)-8s '
                                  '%(message)s '
                                  + '(%(filename)s:%(lineno)s) '
                                  , datefmt='%Y-%m-%d %H:%M:%S')
    fh.setFormatter(formatterFile)
    formatterStdout = logging.Formatter('[%(asctime)s] '
                                  + '%(message)s '
                                  , datefmt='%Y-%m-%d %H:%M:%S')
    ch.setFormatter(formatterStdout)

    # add the handlers to the logger
    logger.addHandler(ch)
    logger.addHandler(fh)

    return logger

logger = create_logger()

def debug(msg):
  logger.debug(msg)

def info(msg):
  logger.info(msg)
  
# logger.log(logging.NOTSET,   "NOTSET   Message - 0")
# logger.log(logging.DEBUG,    "DEBUG    Message - 10")
# logger.log(logging.INFO,     "INFO     Message - 20")
# logger.log(logging.WARNING,  "WARNING  Message - 30")
# logger.log(logging.CRITICAL, "CRITICAL Message - 40")

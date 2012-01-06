'''
File: target.py
Author: Damien Riquet
Description: Remote Python program that monitors incoming and outgoing network packets
             This program features some RPC methods :
                * start_monitor(ip): tell this programs to start to  filter packets according to these ips,
                * stop_monitor(): tell this programs to stop filtering packets according to these ips,
                * get_traffic(): get the traffic associated with the given ip
'''

# Imports
import time
import os
import logging
import pexpect
import re
import sys
import getopt
import threading
from SimpleXMLRPCServer import SimpleXMLRPCServer
from scapy import *

import constant

# Variables
conf.promisc = 0 # Promiscuous mode
logger = logging.getLogger()

# Classes
class Target:
    """ Target class """
    def __init__(self, debug=True):
        # Attributes
        self._monitor = []
        self._traffic = {}

        # Init
        self.init_rpc()
        self.init_logging(debug)

    def init_rpc():
        """ Initialization of RPC remote methods """
        self._server =  SimpleXMLRPCServer(self._addr, allow_none=True)
        # Registering commands
        # self._server.register_function(self.exec_scan_rpc, "exec_scan")

    def init_logging(self, debug=False):
        """ Initialization of the logging module 
            Create log system on both output and file
        """
        # Initialization of loggers
        stream_logger = logging.StreamHandler()
        file_logger = logging.FileHandler("target.log")

        # Adding handlers
        logger.addHandler(stream_logger)
        logger.addHandler(file_logger)

        # Formatting
        stream_formatting = logging.Formatter("%(levelname)s\t: %(message)s")
        file_formatting = logging.Formatter("%(asctime)s %(process)d (%(levelname)s)\t: %(message)s")
        stream_logger.setFormatter(stream_formatting)
        file_logger.setFormatter(file_formatting)

        # Enabling logging
        if debug:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)

            

    def start_monitor(self, ips):
        """ Start a monitoring session filtering to the given ips """
        

# Main
if __name__ == '__main__':
    pass

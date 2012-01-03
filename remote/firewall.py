'''
File: firewall.py
Author: Damien Riquet
Description: Firewall Remote Python program launched on firewall hosts
             It reads log files and detect intrusion (snitch)
             RPC methods are:
                * start_snitch: launch the snitch,
                * stop_snitch: stop the snitch,
                * snitch_state: return the state of the snitch (including detected IPs).

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

import constant


# Variables
logger = logging.getLogger()

class Firewall:
    """ Remote python program that reads log file and alerts top program when some pattern are found """
    def __init__(self, addr, debug=True):
        """ Initialize attributes, rpc methods and logfile to read """
        # Attributes 
        self._addr = addr

        # Snitch data
        self._detected_ips = []
        self._active = False

        # Init RPC / Logging
        self.init_logging(debug)
        self.init_rpc()

    def init_logging(self, debug):
        """ Initialization of the logging module 
            Create log system on both output and file
        """
        # Initialization of loggers
        stream_logger = logging.StreamHandler()
        file_logger = logging.FileHandler("firewall.log")

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

    def init_rpc(self):
        """ Initialization of RPC remote methods """
        self._server =  SimpleXMLRPCServer(self._addr, allow_none=True)
        # Registering commands
        self._server.register_function(self.start_snitch_rpc, "start_snitch")
        self._server.register_function(self.stop_snitch, "stop_snitch")

    def start_snitch_rpc(self, pattern, logfile, timing):
        """ RPC method: launch a thread that creates the snitch """
        t = threading.Timer(0, self.start_snitch, [pattern, logfile, timing])
        t.start()
    
    def start_snitch(self, pattern, logfile, timing):
        """ Create a snitch
            Open the logfile and read it until the coordinator stop the experiment
        """

        logger.info("Starting firewall snitch...")
        logger.info("Pattern: %s" %' '.join(pattern))
        logger.info("logfile: %s" % logfile)
        logger.info("timing: %s" % timing)
        # Initialization
        self._detected_ips = []
        self._active = True

        # Open the file and read it until it has to stop !
        with open(logfile, 'r') as f:
            f.seek(0, os.SEEK_END)

            while self._active:
                # Read the file
                lines = f.readlines()
                lines = ''.join(lines).strip()

                if lines:
                    logger.debug("logfile output: %s" % lines)

                time.sleep(timing)
                


        
    def stop_snitch(self):
        """ Stop the snitch """
        logger.info("Stoping firewall snitch...")
        self._active = False

    def snitch_state(self):
        """docstring for snitch_state"""
        pass



if __name__ == '__main__':
    addr = ('localhost', 8000)
    firewall_snitch = Firewall(addr)

    # Serving forever
    try:
        print "You an stop me at anytime by pressing ^C"
        firewall_snitch._server.serve_forever()
    except KeyboardInterrupt:
        pass

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
        self._server.register_function(self.snitch_state, "snitch_state")

    def start_snitch_rpc(self, pattern, logfile, timing):
        """ RPC method: launch a thread that creates the snitch """
        t = threading.Timer(0, self.start_snitch, [pattern, logfile, timing])
        t.start()
    
    def start_snitch(self, patterns, logfile, timing):
        """ Create a snitch
            Open the logfile and read it until the coordinator stop the experiment
        """

        logger.info("Starting firewall snitch...")
        logger.info("Pattern: %s" %' '.join(patterns))
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

                if len(lines):
                    # There is something on the output
                    for line in lines:
                        logger.debug("logfile output: %s" % line.strip())
                    
                    # Analyse the output
                    self.analyse_output(lines, patterns)
                    


                time.sleep(timing)
                

    def analyse_output(self, lines, patterns):
        """ Analyse output and detect IDSs alerts
            Snort analysis -- possible states :
        """

        alert_pattern_re = re.compile("\[\*\*\] \[.*\] "
                "(?P<alert>.*)"
                " \[\*\*\]\n"
                ".*\n"
                "(?P<time>\d{2}/\d{2}"
                "-\d{2}:\d{2}:\d{2})\.\d+ "
                "(?P<ip_src>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
                " -> "
                "(?P<ip_dst>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
                "\n"
            )

        lines = ''.join(lines)

        for m in alert_pattern_re.finditer(lines):
            # Alert found
            time_str = "%d/%s" % (time.gmtime().tm_year, m.group('time'))

            timestamp = time.strptime(time_str, "%Y/%m/%d-%H:%M:%S")

            logging.info("Alert found: %s -- %s  -- %s -> %s" %
                    (m.group('alert'), time.asctime(timestamp),
                     m.group('ip_src'), m.group('ip_dst')))
    
            alert = m.group('alert')

            # Is there any matching patterns ?
            matching_patterns = []
            for p in patterns:
                if re.search(p.lower(), alert.lower()):
                    matching_patterns.append(p)

            if len(matching_patterns):
                logging.info("Alert matches following patterns: %s" % ', '.join(matching_patterns))

                new_alert = {}
                new_alert['patterns'] = list(matching_patterns)
                new_alert['ip_src'] = m.group('ip_src')
                new_alert['ip_dst'] = m.group('ip_dst')
                new_alert['date'] = time.mktime(timestamp)

                # Adding alert
                self._detected_ips.append(new_alert)




        
    def stop_snitch(self):
        """ Stop the snitch """
        logger.info("Stoping firewall snitch...")
        self._active = False

    def snitch_state(self):
        """ Return the current detected scaners """
        logger.debug("Getting firewall snitch state...")
        return self._detected_ips
        


if __name__ == '__main__':
    addr = ('localhost', 8000)
    firewall_snitch = Firewall(addr)

    firewall_snitch.start_snitch_rpc(['scan', 'portscan'], 'scanner.log', 1)

    while not len(firewall_snitch.snitch_state()):
        time.sleep(1)

    firewall_snitch.stop_snitch()


    # Serving forever
#   try:
#       print "You an stop me at anytime by pressing ^C"
#       firewall_snitch._server.serve_forever()
#   except KeyboardInterrupt:
#       pass

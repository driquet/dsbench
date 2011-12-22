'''
File: scanner.py
Author: Damien Riquet
Description: Remote Python program launched on scanner hosts
             They execute portscans and return:
                * Number of port scanned and their state,
                * Generated traffic while doing the portscan,
                * Timestamps of the beginning and ending of the portscan.
             RPC methods are:
                * exec_scan: execute a portscan,
                * stop_scan: stop a scan and return scan data (described above), 
                * scan_state: return the state of the scan and possibly stop it if scanner host has been detected,

'''

# Imports
import time
import os
import logging
import pexpect
import re

import constant


# Variables
logger = logging.getLogger()

tcp_sent_re = re.compile("SENT" 
        ".*"
        " TCP "
        "(?P<ip_src>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        ":"
        "(?P<port_src>\d{1,5})"
        " > "
        "(?P<ip_dst>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        ":"
        "(?P<port_dst>\d{1,5}) "
        "(?P<flags>\w+)"
        ".*"
        "seq=(?P<seq>\d+)"
       )

tcp_rcvd_re = re.compile("RCVD" 
        ".*"
        " TCP "
        "(?P<ip_src>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        ":"
        "(?P<port_src>\d{1,5})"
        " > "
        "(?P<ip_dst>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        ":"
        "(?P<port_dst>\d{1,5}) "
        "(?P<flags>\w+)"
        ".*"
        "seq=(?P<seq>\d+)"
       )

port_state_re = re.compile("Discovered"
        " (?P<state>\w+) "
        "port (?P<port>\d+)"
        ".* on "
        "(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
       )


class Scanner():
    """ Distributed scanner used in distributed portscan """

    def __init__(self, debug=False):
        """ Initialization """
        ## Initialisation
        self._process = None
        # TODO log, addr

        ## Portscan variables
        self._nbports = 0 # Number of ports being scanned
        self._portstate = {} # Contains all port to be scanned and their state
        self._traffic = {} # Contains the generated traffic
        self._timestamps = {} # Contains timestamps of the beginning and ending of the portscan
        self._logfilename = "" # Filename in which is stored debug messages

        ## Initialization
        self.init_logging(debug)
        # init_rcp()


    def init_logging(self, debug=False):
        """ Initialization of the logging module 
            Create log system on both output and file
        """
        # Initialization of loggers
        stream_logger = logging.StreamHandler()
        file_logger = logging.FileHandler("scanner.log")

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
        self._server =  SimpleXMLRPCServer(addr, allow_none=True)

    def exec_scan(self, scantype, timing, target, ports='-F'):
        """ Execute a portscan """
        ## Portscan variables
        self._nbports = 0
        self._portstate = {} # Contains all port to be scanned and their state
        self._traffic = {} # Contains the generated traffic
        self._timestamps = {} # Contains timestamps of the beginning and ending of the portscan

        day_n_hour = time.strftime("%d-%m-%y_%H-%M-%S")
        self._logfilename = "log/%s_%s.xml" % (constant.types[scantype].split()[0].lower(), day_n_hour) # Filename in which is stored debug messages

        ## Generate Nmap command
        nmap_cmd = "nmap "          \
                   "<type> "        \
                   "<ip> "          \
                   "<ports> "       \
                   "-T <timing> "   \
                   "-d2 "           \
                   "-P0 "           \
                   "-n "            \
                   "--packet-trace "\
                   "-oX <logfile>"

        nmap_cmd = nmap_cmd.replace("<type>", scantype) # Scan type
        nmap_cmd = nmap_cmd.replace("<ip>", target) # Target
        nmap_cmd = nmap_cmd.replace("<timing>", timing) # Timing
        nmap_cmd = nmap_cmd.replace("<logfile>", self._logfilename) # Logfile

        # Ports 
        if isinstance(ports, list):
            nmap_cmd = nmap_cmd.replace("<ports>", "-p %s" % ','.join([str(v) for v in ports]))
            self._nbports = len(ports)
        else:
            nmap_cmd = nmap_cmd.replace("<ports>", ports)
            self._nbports = 100

        logger.info("Building nmap command: %s" % nmap_cmd)
        logger.debug("  Scan type: %s" % scantype)
        logger.debug("  Target: %s" % target)
        logger.debug("  Timing: %s" % timing)
        logger.debug("  Ports: %s" % ports)

        ## Execute Nmap command
        logger.info("Executing command ...")
        self._timestamps['begin'] = time.time()
        self._process = pexpect.spawn(nmap_cmd)

        ## Poll execution regularly and parse debug messages
        expected = [pexpect.EOF, pexpect.TIMEOUT]

        while self._process.isalive():

            # Reading a line
            output = self._process.readline().strip()
            if not output: continue # EOF reached
            
            logger.debug("Nmap.output: %s" % output)

            # Process output
            # Searching data within the nmap output

            ## TCP
            # Sent
            m = tcp_sent_re.search(output)
            if m:
                logger.debug("TCP SENT -- %s:%s -> %s:%s -- flags (%s) -- seq %s"
                        % (m.group('ip_src'), m.group('port_src'), m.group('ip_dst'), m.group('port_dst'), m.group('flags'), m.group('seq')))
                add_traffic_event(self._traffic['sent'], m.group('ip_dst'), int(m.group('port_dst')), (m.group('flags'), m.group('seq')))
                continue

            # Received
            m = tcp_rcvd_re.search(output)
            if m:
                logger.debug("TCP RCVD -- %s:%s -> %s:%s -- flags (%s) -- seq %s"
                        % (m.group('ip_src'), m.group('port_src'), m.group('ip_dst'), m.group('port_dst'), m.group('flags'), m.group('seq')))
                add_traffic_event(self._traffic['rcvd'], m.group('ip_dst'), int(m.group('port_dst')), (m.group('flags'), m.group('seq')))
                continue

            ## Port state
            m = port_state_re.search(output)
            if m:
                logger.info("nbtoscan %d" % self._nbports)
                logger.info("IP %s -- Port %s state: %s" 
                        % (m.group('ip'), m.group('port'), m.group('state')))
                self._nbports -= 1
                if not self._nbports:
                    logger.info("Scan finished")
                self._portstate[int(m.group('port'))] = (m.group('state'), time.time())
                continue

        self._timestamps['end'] = time.time()



        ## Finish the portscan


def add_traffic_event(struct, dst, port, item):
    """ Add a traffic event to the traffic structure """
    # Create intermediary dict
    if dst not in struct:
        struct[dst] = {}
    if port not in struct[dst]:
        struct[dst][port] = []

    # Fill data 
    if struct[dst][port].append(item)



if __name__ == '__main__':
    scanner = Scanner(debug=True)
    scanner.exec_scan('-sS', 'polite', '172.16.0.10', [22,80])


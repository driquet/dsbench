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
                * poll_scan: poll a portscan,
                * stop_scan: stop a scan and return scan data (described above), 
                * scan_state: return the state of the scan and possibly stop it if scanner host has been detected,

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
import xmlrpclib
from SimpleXMLRPCServer import SimpleXMLRPCServer


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
        "(?P<flags>\w+)?"
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

tcp_conn_re = re.compile("CONN"
        ".*"
        "TCP "
        "(?P<ip_src>.*)"
        " > "
        "(?P<ip_dst>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        ":"
        "(?P<port_dst>\d{1,5}) "
       )

port_state_re = re.compile("Discovered"
        " (?P<state>[\w\|]+) "
        "port (?P<port>\d+)"
        ".* on "
        "(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
       )


class Scanner():
    """ Distributed scanner used in distributed portscan """

    def __init__(self, addr = ("localhost", 8000), debug=False):
        """ Initialization """
        ## Initialisation
        self._process = None
        self._addr = addr

        ## Portscan variables
        self._nbports = 0 # Number of ports being scanned
        self._portstate = {} # Contains all port to be scanned and their state
        self._traffic = {} # Contains the generated traffic
        self._timestamps = {} # Contains timestamps of the beginning and ending of the portscan
        self._logfilename = "" # Filename in which is stored debug messages

        ## Initialization
        self.init_logging(debug)
        self.init_rpc()


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
        self._server =  SimpleXMLRPCServer(self._addr, allow_none=True)
        # Registering commands
        self._server.register_function(self.exec_scan_rpc, "exec_scan")
        self._server.register_function(self.stop_scan, "stop_scan")
        self._server.register_function(self.poll_scan, "poll_scan")
        self._server.register_function(self.scan_state, "scan_state")

    def exec_scan_rpc(self, scantype, timing, coordinator, target, ports):
        """ RPC method called: create a thread to launch the portscan """
        t = threading.Timer(0, self.exec_scan, [scantype, timing, coordinator, target, ports])
        t.start()

    def exec_scan(self, scantype, timing, coordinator, target, ports):
        """ Execute a portscan """
        ## Portscan variables
        self._nbports = 0
        self._portstate = {} # Contains all port to be scanned and their state
        self._traffic = {} # Contains the generated traffic
        self._timestamps = {} # Contains timestamps of the beginning and ending of the portscan

        ## Filling traffic structure
        self._traffic['sent'] = {}
        self._traffic['rcvd'] = {}
        self._traffic['both'] = {}

        day_n_hour = time.strftime("%d-%m-%y_%H-%M-%S")
        self._logfilename = "log/%s_%s.xml" % (scantype.lower(), day_n_hour) # Filename in which is stored debug messages

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
        logger.debug("  Coordinator: %s" % coordinator)

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
                flags = m.group('flags')
                if flags == None: flags = ""
                logger.debug("TCP SENT -- %s:%s -> %s:%s -- flags (%s) -- seq %s"
                        % (m.group('ip_src'), m.group('port_src'), m.group('ip_dst'), m.group('port_dst'), flags, m.group('seq')))
                add_traffic_event(self._traffic['sent'], m.group('ip_dst'), m.group('port_dst'), (flags, m.group('seq'), time.time()))
                add_traffic_event(self._traffic['both'], m.group('ip_dst'), m.group('port_dst'), ('out', flags, m.group('seq'), time.time()))
                continue

            # Received
            m = tcp_rcvd_re.search(output)
            if m:
                logger.debug("TCP RCVD -- %s:%s -> %s:%s -- flags (%s) -- seq %s"
                        % (m.group('ip_src'), m.group('port_src'), m.group('ip_dst'), m.group('port_dst'), m.group('flags'), m.group('seq')))
                add_traffic_event(self._traffic['rcvd'], m.group('ip_src'), m.group('port_src'), (m.group('flags'), m.group('seq'), time.time()))
                add_traffic_event(self._traffic['both'], m.group('ip_src'), m.group('port_src'), ('in', m.group('flags'), m.group('seq'), time.time()))
                continue

            # CONNect technique (uses connect function)
            m = tcp_conn_re.search(output)
            if m:
                logger.debug("TCP CONN -- %s -> %s:%s"
                        % (m.group('ip_src'), m.group('ip_dst'), m.group('port_dst')))
                add_traffic_event(self._traffic['sent'], m.group('ip_dst'), m.group('port_dst'), ('S', time.time()))
                add_traffic_event(self._traffic['both'], m.group('ip_dst'), m.group('port_dst'), ('out', 'S', time.time()))
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

                state = m.group('state')
                if state.find('|') != -1:
                    state = state[:state.find('|')]

                self._portstate[m.group('port')] = (state, time.time())
                continue

        self._timestamps['end'] = time.time()


        logger.info("Scan finished")
        # Alert the coordinator that the portscan is finished
        if len(coordinator):
            # Create a RPC proxy and send an alert to the coordinator
            logger.info("Scan finished -- Sending an alert to coordinator %s" % coordinator[0])
            coordinator_proxy = xmlrpclib.ServerProxy("http://%s:%d/" % (coordinator[0], coordinator[1]))
            coordinator_proxy.add_event(('scanner', self._addr[0], target))



    def scan_state(self):
        """ Return state of the current (or not -- at least the last one) portscan """
        return self._portstate, self._traffic

    def stop_scan(self):
        """ Stop the current scan"""
        logger.info("Scan stopped")
        self._process.kill(9)

    def poll_scan(self):
        logger.debug("Scan polled")
        return self._process.isalive()



def add_traffic_event(struct, dst, port, item):
    """ Add a traffic event to the traffic structure """
    # Create intermediary dict
    if dst not in struct:
        print 'creating ', dst
        struct[dst] = {}
    if port not in struct[dst]:
        print 'creating ', port
        struct[dst][port] = []

    # Fill data 
    struct[dst][port].append(item)


def usage(name):
    """ Print usage"""
    print "Usage: python %s <args>" % name
    print "     -h        : print this help"
    print "     -i <ip>   : IP Address reacheable using RPC (default is localhost)"
    print "     -p <port> : Port used for RPC methods (default is 8000)"


if __name__ == '__main__':
    # Variables
    remoteAddr = ("localhost", 8000)

    # Parsing arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'i:p:h')
    except getopt.GetoptError, err:
        print "Bad arguments"
        print str(err)
        usage(args[0])
        sys.exit(2)

    for o, a in opts:
        if o == "-i":
            remoteAddr = (a,remoteAddr[1])
        elif o == "-p":
            remoteAddr = (remoteAddr[0],int(a))
        elif o == "-h":
            usage(sys.argv[0])
            sys.exit(2)
        else:
            print "Unknown option"


    # Initialisation
    scanner = Scanner(remoteAddr, debug=True)

    # Serving forever
    try:
        print "You can stop me at anytime by pressing ^C"
        scanner._server.serve_forever()
    except KeyboardInterrupt:
        pass

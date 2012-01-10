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
import re
import sys
import getopt
import threading
from SimpleXMLRPCServer import SimpleXMLRPCServer
from scapy.all import *

# Variables
logger = logging.getLogger()

# Classes
class Target:
    """ Target class """
    def __init__(self, interface="eth0", addr=("localhost", 8000), debug=True):
        # Attributes
        self._monitor = []
        self._traffic = {}
        self._addr = addr

        # Init
        self.init_rpc()
        self.init_logging(debug)

        # Monitor attributes
        self._active = False
        self._iface = interface

    def init_rpc(self):
        """ Initialization of RPC remote methods """
        self._server =  SimpleXMLRPCServer(self._addr, allow_none=True)
        # Registering commands
        self._server.register_function(self.start_monitor_rpc, "start_monitor")
        self._server.register_function(self.stop_monitor, "stop_monitor")
        self._server.register_function(self.get_traffic, "get_traffic")

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

            
    def start_monitor_rpc(self, ips):
        """ RPC method: launch a thread that creates the snitch """
        t = threading.Timer(0, self.start_monitor, [ips])
        t.start()

    def stop_monitor(self):
        """ Stop the monitor """
        logger.info("Stopping the monitor ...")
        self._active = False

    def get_traffic(self):
        """ Return the traffic monitored """
        logger.info("Getting the monitored traffic")
        return self._traffic

    def start_monitor(self, ips):
        """ Start a monitoring session filtering to the given ips """
        # Create the scapy socket
        lsock = L2ListenSocket(iface=self._iface, promisc=0)

        self._active = True
        self._traffic = {}

        while self._active:
            # Receive instruction
            pkt = lsock.recv(MTU)
            logger.debug("Received a packet")

            # Filter tcp packet
            if not pkt.haslayer('TCP'):
                logger.debug("Not a tcp packet")
                continue

            # Filter monitored ips
            if not (pkt.sprintf("%IP.src%") in ips) and \
               not (pkt.sprintf("%IP.dst%") in ips):
                logger.debug("Packet outside monitored hosts list - %s or %s" % (pkt.sprintf("%IP.dst%"), pkt.sprintf("%IP.src%")))
                continue

            # Fetching data
            ip_src = pkt.sprintf("%IP.src%")
            ip_dst = pkt.sprintf("%IP.dst%")
            tcp_sport = pkt.sprintf("%r,TCP.sport%")
            tcp_dport = pkt.sprintf("%r,TCP.dport%")
            ip_flags = pkt.sprintf("%TCP.flags%")
            ip_seq = pkt.sprintf("%TCP.seq%")
            pkt_time = pkt.sprintf("%.time%")

            # Processing data
            pkt_time = "%d/%d/%d %s" % (time.gmtime().tm_mday, time.gmtime().tm_mon, time.gmtime().tm_year, pkt_time)
            pkt_time = pkt_time.split('.')[0]
            pkt_time = time.mktime(time.strptime(pkt_time, "%d/%m/%Y %H:%M:%S"))

            # Classify traffic
            if ip_src in ips:
                # Received packet
                ip_scanner = ip_src
                ip_target = ip_dst
                target_port = tcp_dport
                logger.info("RCVD PKT - %s -> %s:%s - flags %s - seq %s" %
                        (ip_scanner, ip_target, target_port, ip_flags, ip_seq))
            else:
                # Sent packet
                ip_scanner = ip_dst
                ip_target = ip_src
                target_port = tcp_sport
                logger.info("SENT PKT - %s -> %s:%s - flags %s - seq %s" %
                        (ip_scanner, ip_target, target_port, ip_flags, ip_seq))


            # Create dict and list if needed
            if ip_scanner not in self._traffic:
                self._traffic[ip_scanner] = {}
            if target_port not in self._traffic[ip_scanner]:
                self._traffic[ip_scanner][target_port] = []


            pkt_info = (ip_flags, ip_seq, pkt_time)
            logger.debug(pkt_info)
            self._traffic[ip_scanner][target_port].append(pkt_info)


        lsock.close()
        
        

# Main
if __name__ == '__main__':
    # Variables
    remoteAddr = ("localhost", 8000)
    interface = "eth0"

    # Parsing arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'd:i:p:')
    except getopt.GetoptError, err:
        print "Bad arguments"
        print str(err)
        sys.exit(2)

    for o, a in opts:
        if o == "-d":
            interface = a
        elif o == "-i":
            remoteAddr = (a,remoteAddr[1])
        elif o == "-p":
            remoteAddr = (remoteAddr[0],int(a))
        else:
            print "Unknown option"

    # Initialisation
    target = Target(interface, remoteAddr, debug=True)

    # Serving forever
    try:
        print "You an stop me at anytime by pressing ^C"
        target._server.serve_forever()
    except KeyboardInterrupt:
        pass

#!/usr/bin/python

'''
File: coordinator.py
Author: Damien Riquet
Description: Python program coordinating scanners, firewalls and targets
'''

# Imports
import re
import getopt
import sys
import xmlrpclib
import time
import json
import logging


# Variables
logger = logging.getLogger()

def usage(name):
    """ Print usage"""
    print "Usage: python %s <args>" % name
    print "     -h        : print this help"
    print "     -c <conf> : Configuration file"


def init_logging(debug):
    """ Initialization of the logging module 
        Create log system on both output and file
    """
    # Initialization of loggers
    stream_logger = logging.StreamHandler()
    file_logger = logging.FileHandler("coordinator.log")

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


def parse_configuration_file(conf_file):
    """ Parse configuration file """
    logger.info("Parsing file %s" % conf_file)
    with open(conf_file) as f:
        conf = json.loads(f.read())

        # Processing hosts element, searching for set element within IPs
        for s in ['scanners', 'targets', 'firewalls']:
            s_hosts = []
            for host in conf['hosts'][s]:
                logger.debug("Trying to expand %s hosts - %s" % (s, host['ip']))
                pattern = re.compile("(?P<base>\d{1,3}\.\d{1,3}\.\d{1,3}\.)"
                                     "(?P<begin>\d{1,3})-(?P<end>\d{1,3})")
                match = pattern.search(host['ip'])

                if not match:
                    s_hosts.append(host)
                else:
                    base = match.group('base')
                    begin = int(match.group('begin'))
                    end = int(match.group('end'))
                    port = host['port']

                    # Remove the old value
                    conf['hosts'][s].remove(host)

                    # Generate new one
                    for i in range(begin, end+1):
                        host = {}
                        host['ip'] = "%s%d" % (base, i)
                        host['port'] = port
                        
                        # Add new value
                        s_hosts.append(host)
            conf['hosts'][s] = s_hosts

        return conf



if __name__ == '__main__':
    # Variables
    conf = None
    debug = True

    # Parsing arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'c:hd')
    except getopt.GetoptError, err:
        print "Bad arguments"
        print str(err)
        usage(sys.argv[0])
        sys.exit(2)

    for o, a in opts:
        if o == "-c":
            conf = a
        elif o == "-h":
            usage(sys.argv[0])
            sys.exit(2)
        elif o == "-d":
            debug = True
        else:
            print "Unknown option"

    # Arguments verification
    if not conf:
        usage(sys.argv[0])
        sys.exit(2)

    # logging Init
    init_logging(debug)

    # Parse configuration file
    conf = parse_configuration_file(conf)

    




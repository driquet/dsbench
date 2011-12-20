#!/usr/bin/python

'''
File: experiment.py
Author: Damien Riquet
Description: Make a many to many experiment
'''

# Imports
import core.common as common
import getopt
import xmlrpclib
import sys


# Variables
# --- Register
register = ("172.16.0.1", 8000)
reg_proxy = xmlrpclib.ServerProxy("http://%s:%d/" % register)

firewall = ("172.16.0.2", 8000)
fw_proxy = xmlrpclib.ServerProxy("http://%s:%d/" % firewall )

def usage():
    print "usage"


if __name__ == '__main__':
    # handling args
    try:
        opts, args = getopt.getopt(sys.argv[1:], "m:ha:v:t:l:" , [])
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(2)

    # parsing args
    modes = []
    timings = []
    attackers = []
    victims = []
    logname = None

    try:
        for o, a in opts:
            if o in ('-m'):
                modes.append(a)
            if o in ("-h"):
                usage()
                sys.exit()
            elif o == "-a":
                attackers.append((a,8000))
            elif o == "-v":
                victims.append(a)
            elif o == "-t":
                timings.append(a)
            elif o == "-l":
                logname = a


    except ValueError, Exception:
        print "One or several arguments are not valid"
        print sys.exc_info()[0]
        usage()
        sys.exit(2)


    
    if len(attackers) == 0 or \
       len(victims)   == 0 or \
       len(timings)   == 0 or \
       logname        == None or \
       len(modes)     == 0:
        usage()
        sys.exit()


    common.log("Attackers are : %s" % attackers)
    common.log("Victims are   : %s" % victims)
    common.log("Timings are   : %s" % timings)
    common.log("Modes are     : %s" % modes)
    common.log("Log will be stored at : %s" % logname)

    try:
        print "You can stop me anytime by pressing ^C"
    except KeyboardInterrupt:
        # TODO arreter tous les process chez les remotes
        pass


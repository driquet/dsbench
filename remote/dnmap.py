#!/usr/bin/python

'''
File: dnmap.py
Author: Damien Riquet
Description: Make a many to many experiment
'''

# Imports
import core.common as common
import core.constant as constant
from experiment import *
import getopt
import xmlrpclib
import sys


# Variables
# --- Register
register = ("192.168.0.1", 8000)
reg_proxy = xmlrpclib.ServerProxy("http://%s:%d/" % register)

firewall = ("192.168.0.2", 8000)
fw_proxy = xmlrpclib.ServerProxy("http://%s:%d/" % firewall )

def usage(cmd):
    print "Usage : %s [OPTION]..." % (cmd)
    print "     -h : print this help"
    print "     -m <value> : mode [naive, parallel, interlaced]"
    print "     -a <value> : IP of an attacker"
    print "     -v <value> : IP of a victim"
    print "     -t <value> : timing of attacks [insane, aggressive, normal, polite, sneaky, paranoid]"
    print "     -f <value> : IP of a firewall"
    print "     -l <value> : path to the log directory"
    print "     -o <value> : option of attacks [sS, sT, sR, ..., sN]"
    print "     -n <value> : enable log for specified number of attackers"
    print "     -p <value> : process attacks for the specified number of victims"
    print "     -c <value> : number of time each experiment has to be run"

if __name__ == '__main__':
    # handling args
    try:
        opts, args = getopt.getopt(sys.argv[1:], "m:ha:v:t:f:l:o:n:p:c:" , [])
    except getopt.GetoptError, err:
        print str(err)
        usage(sys.argv[0])
        sys.exit(2)

    # parsing args
    modes = []
    timings = []
    types = []
    attackers = []
    log_nb_attackers = []
    nb_victims = []
    victims = []
    firewalls = []
    logdir = None
    count = 1

    try:
        for o, a in opts:
            if o in ("-h"):
                usage()
                sys.exit()
            elif o in ('-m'):
                modes.append(a)
            elif o == "-a":
                attackers.append((a,8000))
            elif o == "-v":
                victims.append(a)
            elif o == "-f":
                firewalls.append((a, 8000))
            elif o == "-t":
                timings.append(a)
            elif o == "-l":
                logdir = a
            elif o == "-o":
                opt = "-%s" % (a)
                types.append((opt,constant.types[opt]))
            elif o == "-n":
                log_nb_attackers.append(int(a))
            elif o == "-p":
                nb_victims.append(int(a))
            elif o == "-c":
                count = int(a)

    except ValueError, Exception:
        print "One or several arguments are not valid"
        print sys.exc_info()[0]
        usage(sys.argv[0])
        sys.exit(2)


    if len(attackers) == 0 or \
       len(victims)   == 0 or \
       len(timings)   == 0 or \
       len(modes)     == 0 or \
       len(types)     == 0 or \
       len(firewalls) == 0 or \
       len(nb_victims) == 0 or \
       len(log_nb_attackers) == 0:
        usage(sys.argv[0])
        sys.exit()

    log_nb_attackers.sort()

    common.log("Attackers are : %s" % attackers)
    common.log("Victims are   : %s" % victims)
    common.log("Timings are   : %s" % timings)
    common.log("Modes are     : %s" % modes)
    common.log("nb_attackers are     : %s" % log_nb_attackers)
    common.log("nb_victims are     : %s" % nb_victims)

    try:
        print "You can stop me anytime by pressing ^C"

        for i in range(count):
            common.log("### COUNT %d ###" % count)
            for nb_victim in nb_victims:
                common.log("##### Nb victims %d " % nb_victim)
                vic = victims[:nb_victim]
                for mode in modes:
                    common.log("########### Mode %s ###########" % mode)
                    if mode == "naive": algo = naive
                    elif mode == "parallel": algo = parallel
                    elif mode == "interlaced": algo = parallel

                    runner = algo.Algorithm(attackers, vic, types, timings, firewalls, log_nb_attackers, logdir)
                    runner.run()

                    common.log("########### Mode %s ###########" % mode)

            common.log("### COUNT %d ###" % count)


    except KeyboardInterrupt:
        # TODO arreter tous les process chez les remotes
        pass


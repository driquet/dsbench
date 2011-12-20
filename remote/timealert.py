#!/usr/bin/python

'''
File: timealert.py
Author: Damien Riquet
Description: Script which measure how long it takes to alert an attack
'''

# Imports
import time
import os
import sys
import getopt
import re

# Variables
default_timing = 0.5
default_pattern = "nmap"

class State:
    INIT = 0
    FOUND = 1
    IP = 2
    cpt = 0

def usage():
    """ print usage """
    print "Usage <namescript> <args>"
    print "     args are :"
    print "     -h,--help    : print usage"
    print "     -f,--file    : file path"
    print "     -t,--timing  : delay between reads"
    print "     -p,--pattern : pattern to look for"

def main(file, timing, pattern):
    """ open a file, read it until it finds the pattern """

    # Initialisation : opening the file, fixing the timer
    print "[timealert] Initialisation"
    sys.stdout.flush()

    f = open(file,"r")
    f.seek(0, os.SEEK_END)

    state = State.INIT
    ip = ""

    time_b = time.time()
    print "[timealert] Reading beginned at %s" % (time.ctime(time_b))
    print "[timealert] Loop"
    sys.stdout.flush()

    while True:


        v = True
        while v:
            line = f.readline()
            if not line:
                time.sleep(timing)
                continue

            if state == State.INIT:
                for p in pattern:
                    if line.lower().find(p) != -1:
                        state = State.FOUND

            elif state == State.FOUND:
               state = State.IP

            elif state == State.IP:
                state = State.INIT
                m = re.search("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",line)
                if m != None:
                    ip = m.group(1)
                    v = False

        time_e = time.time()
        time_elapsed = time_e - time_b

        print "%.2f secs to find the pattern %s from file %s - IP %s - timestamp %f" % (time_elapsed, pattern, file, ip, time.time())
        sys.stdout.flush()

if __name__ == '__main__':
    # handling args
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hf:t:p:" , ["help", "file=","timing=", "pattern="])
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(2)

    # parsing args
    file = None
    timing = default_timing
    pattern = [default_pattern]

    try:
        for o, a in opts:
            if o in ("-h", "--help"):
                usage()
                sys.exit()
            elif o in ("-f", "--file"):
                file = a
            elif o in ("-t", "--timing"):
                timing = float(a)
            elif o in ("-p", "--pattern"):
                pattern.append(a)

        if file == None:
            usage()
            sys.exit()
    except ValueError, Exception:
        print "One or several arguments are not valid"
        print sys.exc_info()[0]
        usage()
        sys.exit(2)

    # main
    main(file, timing, pattern)

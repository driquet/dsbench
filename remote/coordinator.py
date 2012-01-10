#!/usr/bin/python

'''
File: coordinator.py
Author: Damien Riquet
Description: Python program coordinating scanners, firewalls and targets
'''

# Imports
import xmlrpclib
import time

if __name__ == '__main__':
#   scanner_addr = ("localhost", 8000)
#   scanner = xmlrpclib.ServerProxy("http://%s:%d/" % scanner_addr)

#   scanner.start_scan('-sS', 'polite', '172.16.0.10', [22,80])
#   while scanner.poll_scan():
#       time.w
#   states, traffic = scanner.scan_state()

#   for port, state in states.items():
#       print port, state[0], state[1]

#   print

#   for dst in traffic['both']:
#       for port in traffic['both'][dst]:
#           print port, traffic['both'][dst][port]

    target_addr = ('172.16.0.10', 8000)
    target = xmlrpclib.ServerProxy("http://%s:%d/" % target_addr)

    target.start_monitor(["172.16.0.1"])

    time.sleep(2)
    target.stop_monitor()
    traffic = target.get_traffic()

    for scanner in traffic:
        print "scanner", scanner
        for port in traffic[scanner]:
            print "    port", port
            for pkt in traffic[scanner][port]:
                print "        pkt", pkt


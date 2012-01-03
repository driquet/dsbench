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

    firewall_addr = ('localhost', 8000)
    firewall = xmlrpclib.ServerProxy("http://%s:%d/" % firewall_addr)

    firewall.start_snitch(['toto', 'pwet'], 'scanner.log', 0.1)

    time.sleep(20)

    firewall.stop_snitch()

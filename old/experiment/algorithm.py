'''
File: algo.py
Author: Damien Riquet
Description: Define the Algorithm class
'''

# Imports
import random
import xmlrpclib

class Algorithm():
    """ Algorithm class
            attackers : Remote hosts used to attack
            victims : Remotes hosts targeted
            types : Different kinds of attack
            timings : Timings used for these attacks
    """

    def __init__(self, attackers, victims, types, timings, firewalls, log_nb_attackers, logdir):
        self.attackers = attackers
        self.victims = victims
        self.types = types
        self.timings = timings
        self.firewalls = firewalls
        self.logdir = logdir
        self.log_nb_attackers = log_nb_attackers

        self.logdir = str(len(victims))

        self.initproxies()


    def initproxies(self):
        """ Initialize proxies """
        self.proxy_attackers = {}
        self.proxy_firewalls = {}

        for attacker in self.attackers:
            self.proxy_attackers[attacker] = xmlrpclib.ServerProxy("http://%s:%d/" % attacker)

        for firewall in self.firewalls:
            self.proxy_firewalls[firewall] = xmlrpclib.ServerProxy("http://%s:%d/" % firewall)



    def generate(self, victims, ports, nbgroup=0):
        """ Generate subparts of the portscanning """
        subparts = []
        nbports = len(ports)
        if nbgroup == 0:
            portspergroup = 3
            nbgroup = nbports / portspergroup
        else:
            portspergroup = nbports / nbgroup
        for victim in victims:
            random.shuffle(ports, random.random)
            for i in range(0, nbgroup):
                subparts.append((victim,ports[i*portspergroup:(i+1)*portspergroup]))
            if nbports % portspergroup != 0:
                # Last subpart
                subparts.append((victim,ports[nbgroup*portspergroup+1:]))
        return subparts

    def run(self):
        pass

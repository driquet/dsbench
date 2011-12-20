#!/usr/bin/python


'''
File: naive.py
Author: Damien Riquet
Description: Naive Algorithm
        While an attacker is not detected, he scans targets
        When an attacker is detected, the algorithm takes the next to do the same
'''

import algorithm
import core.common as common
import core.constant as constant
import random
import time
import sys

class Algorithm(algorithm.Algorithm):

    def run(self):
        """ Run the experiment """
        common.log("Main")
        fw_proxy = self.proxy_firewalls[self.firewalls[0]]

        # Starting alert timer at the firewall
        time.sleep(1.5)
        fw_proxy.run("/etc/init.d/snort restart")
        time.sleep(1.5)
        fw_proxy.run(constant.fw_cmd)
        common.log("  >> [Firewall : %s:%d] %s" % (self.firewalls[0][0], self.firewalls[0][1], constant.fw_cmd))

        for timing in self.timings:


            common.log("Naive Algorithm")
            common.log("  %d attackers" % len(self.attackers))
            common.log("  %d victims" % len(self.victims))

            common.log("")
            common.log(">> Timing %s" % timing)
            for option, type in self.types :
                common.log("")
                common.log("")
                common.log("  >> Type %s" % type)

                # Building command(s)
                subparts = self.generate(self.victims, constant.mostusedports)
                random.shuffle(subparts)
                common.log("  >> Generating %d subparts" % len(subparts))


                remotes = list(self.attackers)

                nb_detected = 0
                i_subpart = 0
                i_remote = 0
                for remote in remotes:


                    # Connecting to the remote host
                    remote_proxy = self.proxy_attackers[remote]

                    undetected = True
                    while undetected:

                        if i_subpart == len(subparts):
                            break

                        subpart = subparts[i_subpart]
                        i_subpart += 1

                        # Creating the command
                        cmd = common.convert(subpart, option, timing)
                        common.log("    >> [Remote : %s:%d][Subpart : %s - %d/%d][Remote %d/%d]"
                                % (remote[0], remote[1], cmd, i_subpart, len(subparts), i_remote, len(remotes)))


                        remote_proxy.run(cmd)
                        sys.stdout.write("[%s]     << Waiting : " % (time.ctime()))
                        sys.stdout.flush()

                        while True:
                            status = remote_proxy.poll()
                            if not status:
                                status = fw_proxy.pollfw()
                                if status != None and status != False:
                                    undetected = False
                                else:
                                    undetected = True
                                break

                            status = fw_proxy.pollfw()
                            if status != None and status != False:
                                undetected = False
                                remote_proxy.kill()
                                break


                            sys.stdout.write('.')
                            sys.stdout.flush()
                            common.timing_sleep(timing)


                        str = "Undetected"
                        if not undetected:
                            str = "Detected"
                            fw_proxy.kill()                        
                            fw_proxy.run(constant.fw_cmd)
                            time.sleep(0.5)
                        sys.stdout.write(" >> %s\n" % str)
                        sys.stdout.flush()




                    if not undetected:
                        nb_detected += 1
                    i_remote +=1
                    

                    # Log time

                    if i_remote in self.log_nb_attackers:
                        percentage = float(i_subpart)/len(subparts) * 100
                        message = "%s - [Remotes detected : %d/%d][Scan accomplished : %.2f%%]" % (str, i_remote, len(remotes), percentage)
                        common.log(message)
                        common.logtype(type, timing, message, percentage, 'naive', self.logdir, '../log/', i_remote)

                    if i_subpart == len(subparts):
                        # Scan has finished
                        percentage = 100
                        message = "%s - [Remotes detected : %d/%d][Scan accomplished : %.2f%%]" % (str, i_remote, len(remotes), percentage)
                        for i in self.log_nb_attackers:
                            if i > i_remote:
                                common.log(message)
                                common.logtype(type, timing, message, percentage, 'naive', self.logdir, '../log/', i)
                        break

                            
                common.log("  << Type %s" % type)
            common.log("<< Timing %s" % timing)

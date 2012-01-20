#!/usr/bin/python


'''
File: parallel.py
Author: Damien Riquet
Description: Parallel Algorithm
        All scan are launched at the same time
'''

import algorithm
import core.common as common
import core.constant as constant
import random
import time

class Algorithm(algorithm.Algorithm):


    def run(self):
        """ Run the experiment """
        common.log("Main")
        fw_proxy = self.proxy_firewalls[self.firewalls[0]]


        # Starting alert timer at the firewall
        for timing in self.timings:
            for nb_attackers in self.log_nb_attackers:
                attackers = self.attackers[:nb_attackers]
                common.log("")
                common.log(">> Timing %s" % timing)
                for option, type in self.types :
                    for j in range(1,4):
                        common.log("")
                        common.log("")
                        #common.log("Restarting snort")
                        #fw_proxy.run("/etc/init.d/snort stop")
                        #fw_proxy.run("/etc/init.d/snort start")
                        fw_proxy.run(constant.fw_cmd)
                        common.log("  >> [Firewall : %s:%d] %s" % (self.firewalls[0][0], self.firewalls[0][1], constant.fw_cmd))
                        time.sleep(4)

                        common.log("")
                        common.log("  >> Type %s" % type)

                        # Building command(s)
                        subparts = self.generate(self.victims, constant.mostusedports, len(attackers))
                        random.shuffle(subparts)
                        common.log("  >> Generating %d subparts" % len(subparts))


                        nb_detected = 0
                        i_remote = 0

                        subpartsperremotes = len(subparts) / len(attackers)

                        # Dispatching commands
                        commands = {}
                        for remote in attackers:
                            commands[remote] = []
                            for i in range(i_remote * subpartsperremotes, (i_remote + 1) * subpartsperremotes):
                                command = common.convert(subparts[i], option, timing)
                                commands[remote].append(command)
                            i_remote += 1

                        if len(subparts) % len(attackers) != 0:
                            i_remote = 0
                            for i in range(i_remote * subpartsperremotes + 1, len(attackers)):
                                command = common.convert(subparts[i], option, timing)
                                commands[attackers[i_remote]].append(command)
                                i_remote += 1


                        i_remote = 0

                        # Loading scan on all remotes
                        for remote in attackers:
                            # Connecting to the remote host
                            i_remote += 1
                            remote_proxy = self.proxy_attackers[remote]
                            remote_commands = commands[remote]

                            common.log("    >> LOADING [Remote : %s:%d][Nb Subparts :  %d/%d][Remote %d/%d]"
                                    % (remote[0], remote[1], len(remote_commands), len(subparts), i_remote, len(attackers)))

                            # Sending command
                            remote_proxy.loadmultiple(remote_commands)

                            # Sending command
                            remote_proxy.runmultiple()
                            common.log("    >> RUN     [Remote : %s:%d][Nb Subparts :  %d/%d][Remote %d/%d]"
                                    % (remote[0], remote[1], len(remote_commands), len(subparts), i_remote, len(attackers)))


                        common.log("    >> Monitoring")
                        time.sleep(0.5)

                        # Monitoring remotes
                        remotes = list(attackers)
                        common.log("        << Waitings scans to be finished >>")
                        while len(remotes) != 0:
                            for remote in remotes:
                                remote_proxy = self.proxy_attackers[remote]
                                try:
                                    if not remote_proxy.poll():
                                        remotes.remove(remote)
                                        common.log("          => Scan finished for remote %s" % remote[0])
                                except:
                                    pass
                        common.log("        << Scans are finished >>")

                        time.sleep(0.5)
                        # Monitoring firewall state
                        common.log("        << Asking firewall state >>")
                        remotes_percentage = dict([remote[0], [False, 100]] for remote in attackers)
                        # Fetching timestamps
                        # Fetching detected scanners list
                        detected = fw_proxy.pollfw()

                        percentage = 100
                        if detected != None and detected != False:
                            percentage = 0
                            for ip, timestamp in detected[1]:
                                if ip in remotes_percentage and not remotes_percentage[ip][0]:
                                    nb_detected += 1
                                    remotes_percentage[ip][0] = True

                                    # Compute remote percentage
                                    remote_percentage = 0
                                    remote_proxy = self.proxy_attackers[(ip,8000)]
                                    detection_timestamp = float(timestamp)
                                    remote_timestamps = remote_proxy.gettimestamps()
                                    for remote_timestamp in remote_timestamps:                                
                                        if len(remote_timestamp) == 1:
                                            remote_timestamp.append(time.time())
                                        remote_duration = remote_timestamp[1] - remote_timestamp[0]
                                        remote_detection = detection_timestamp - remote_timestamp[0]
                                        remote_percentage += max(0, float(remote_detection) / remote_duration)
                                    remote_percentage /= len(remote_timestamps)
                                    remote_percentage *= 100
                                    remote_percentage = min(remote_percentage,100)
                                    percentage += remote_percentage

                                    common.log("    /!\ Scanner detected : IP %s - Stopped at %.2f%% " % (ip, remote_percentage))
                            percentage += (len(attackers) - nb_detected) * 100
                            percentage /= len(attackers)


                        message = "Scan accomplished [%.2f%%] - [detected %d/%d]" % (percentage, nb_detected, len(attackers)) 

                        common.logtype(type, timing, message, percentage, 'parallel', self.logdir, '../log/', len(attackers))
                        message = "%s - [Scan accomplished : %.2f%%]" % (message, percentage)
                        common.log(message)




                    fw_proxy.kill()
                    common.log("  << Type %s" % type)
                common.log("<< Timing %s" % timing)

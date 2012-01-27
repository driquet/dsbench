'''
File: parallel.py
Author: Damien Riquet
Description: Parallel way to distribute portscan

             Parallel distribution consists in:
                * divide the whole set containing (targets, ports) into subparts,
                * start firewalls monitor
                * distribute these subparts between scanners,
                * wait for events and process them

             Events can be:
                * the scanner has finished its work, we give it work it there is left,
                * or one of the firewall has detected a scanner, and we have to stop it.

'''

# imports
import distribution 

class Parallel(distribution.DistributionMethod):

    def run_experiment(self):
        """ Run the experiment using this distribution method 
            This method has to be implemented in inherited classes
        """
        ## 0) Experiment variables
        scan_method = self._conf['scan_method']
        scan_timing = self._conf['scan_timing']
        ports = self._conf['ports']

        detected_scanners = []
        self._current_jobs = 0


        ## 1) Generate subparts of the whole set
        self._logger.info("Generating subparts ...")
        subparts = self.generate_subparts()
        self._logger.info("%d subparts generated" % len(subparts))


        ## 2) Start firewalls monitor
        for firewall_ip, firewall_rpc in self._p_firewalls.items():
            args = self._conf['firewall_args']
            self._logger.info("Starting monitor of the firewall %s" % firewall_ip)
            firewall_rpc.start_snitch(args['patterns'], args['logfile'], args['timing'], self._addr)
        

        ## 3) Distribute subparts between scanners (First time)
        for scanner_ip, scanner_rpc in self._p_scanners.items():

            # Verifying there are subparts
            if len(subparts):
                self.distribute_subpart(subparts, scanner_ip)
            
             
        ## 4) Wait for events and the end of the experiment
        while not len(subparts) or len(detected_scanner) != self._conf['nb_scanners'] or self._current_jobs:
            # While there are subparts to process OR scanners undetected OR current jobs, waiting for signals

            if len(self._events):
                # There are events, process them all
                
                while len(self._events):
                    # Pop the first event
                    event = self._events.pop(0)

                    # An event could be :
                    #   * a scanner that has finished his subpart,  event = ('scanner', scanner_ip, target_ip)
                    #   * a firewall that has detected a scanner, event = ('firewall', alert)
                    #     with alert a dict containing 'patterns', 'detected_by', 'ip_src', 'ip_dst' and 'date' values

                    if event[0] == 'scanner':
                        # A scanner has finished his work
                        # We need to 1) update traffic and ports database and 2) give a job back to the scanner, if possible

                        self._current_jobs -= 1

                        scanner_ip = event[1]
                        target_ip = event[2]
                        self._logger.info("Scanner %s has finished its portscan" % (scanner_ip))


                        if scanner_ip not in self._p_scanners:
                            # Unknown scanner
                            continue

                        scanner_rpc = self._p_scanners[scanner_ip]

                        # 1) Fetch data about the portscan and update local data
                        ports_state, generated_traffic = scanner_rpc.scan_state() 

                        # Updating self._portstate['scanners'] data
                        update_port_state(ports_state, scanner_ip, target_ip)

                        # Updating self._traffic['scanners'] data
                        self.update_traffic(generated_traffic, scanner_ip)


                        # 2) Giving job back to the scanner
                        if len(subparts) and scanner_ip not in detected_scanners:
                            self.distribute_subpart(subparts, scanner_ip)


                    elif event[0] == 'firewall':
                        # A firewall has detected a scanner
                        # We need to stop the scanner, put it in the detected scanners list, update the traffic and ports database

                        detected_scanner_ip  = event[1]['ip_src']
                        target = event[1]['ip_dst']
                        detected_scanner_rpc = self._p_scanners[detected_scanner_ip]

                        # 1) Stop the scanner and fetch its results
                        detected_scanner_rpc.stop_scan()
                        ports_state, generated_traffic = detected_scanner_rpc.scan_state() 
        
                        # Updating self._portstate['scanners'] data
                        update_port_state(ports_state, detected_scanner_ip, target)

                        # Updating self._traffic['scanners'] data
                        self.update_traffic(generated_traffic, detected_scanner_ip)

                        # 2) Add the scanner to the detected list
                        detected_scanners.append(detected_scanner_ip)




                    else:
                        continue

            # Sleep between each loop
            time.sleep(0.1)

                

                
        
    def update_traffic(self, generated_traffic, scanner):
        """ Update local data, add generated traffic by scanner """
        for target in generated_traffic:
            for port in generated_traffic[target]:
                for pkt_info in generated_traffic[target][port]:
                    # pkt_info is a list that contains (flags, seq, time) values
                    # We only keep flags and seq values
                    
                    # Creating structures if non-existent
                    if scanner not in self._traffic['scanners']:
                        self._traffic['scanners'][scanner] = {}

                    if target not in self._traffic['scanners'][scanner]:
                        self._traffic['scanners'][scanner][target] = {}

                    if port not in self._traffic['scanners'][scanner][port]:
                        self._traffic['scanners'][scanner][target][port] = []

                    # Updating data
                    self._traffic['scanners'][scanner][target][port].append(pkt_info[0], pkt_info[1])


    def update_port_state(self, ports_state, scanner, target):
        """ Update local data, add port state found by the scanner """
        for port, port_state in ports_state.items():

            # Creating the structure if non-existent
            if target not in self._portstate['scanners']:
                self._portstate['scanners'][target] = {}


            self._logger.debug('Scanner %s found that %s:%s is %s' % (scanner, target, port, port_state))
            self._portstate['scanners'][target][port] = (port_state, scanner)
        

    def distribute_subpart(self, subparts, scanner):
        """ Send a subpart to a scanner """
        subpart = subparts.pop()
        self._current_jobs += 1

        # Send RPC request to the scanner
        self._logger.info("Call to %s.exec_scan method - %d ports to scan" % (scanner, len(subpart[1])))
        scanner_rpc = self._p_scanners[scanner]

        scanner_rpc.exec_scan(self._conf['scan_method'], self._conf['scan_timing'], subpart[0], subpart[1], self._addr)
        

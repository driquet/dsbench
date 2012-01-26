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
        for scanner_rpc in self._p_scanners:
            subpart = subparts.pop()
            
            scanner_rpc.exec_scan
        



        ## 4) Wait for events


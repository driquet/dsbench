'''
File: distribution.py
Author: Damien Riquet
Description: Skeleton of a distribution method
             Actual way to distribute attack is described using this abstract class

             Main methods are:
                * pre_experiment: initialize the distribution method,
                * run_experiment: run
                * post_experiment: create backup, etc.
'''

# Imports
import time
import random
import xmlrpclib
import logging
import threading

from SimpleXMLRPCServer import SimpleXMLRPCServer



class DistributionMethod():
    """ Distribution Method class
        Represents a way to distribute attacks
    """

    def __init__(self, logger, conf, addr):
        """ Initialize a Distribution Method """
        # Attributes
        self._logger = logger
        self._conf = conf
        self._detected_scanners = []
        self._events = []
        self._addr = addr

        ## Attributes related to results 
        # Traffic contains traffic generated by scanners and receveived by targets
        self._traffic = {}
        self._traffic['scanners'] = {}
        self._traffic['targets'] = {}

        # Port state contains real port states of target hosts and port states found by scanners during portscan
        self._portstate = {}
        self._portstate['scanners'] = {}
        self._portstate['targets'] = {}


# ########## Main methods 

    def pre_experiment(self):
        """ Method called before a experiment is launched """
        # Init RPC proxies and methods
        self.init_rpc()

        # Start firewall and target monitoring 
        self.start_monitoring()



    def run_experiment(self):
        """ Run the experiment using this distribution method 
            This method has to be implemented in inherited classes
        """
        pass


    def post_experiment(self):
        """ Process all action that has to be done after an experiment
            For example: compute the Attacker Success Rate, create back_up, etc.

        """

        # Stop monitoring, fetch traffic captured by targets and open ports
        self.stop_monitoring()
        self.update_targets_data()

        # Compute results, including ASR
        ASR = self.compute_experiment_result()

        # Back up log files
        # TODO

        # Stop RPC services
        self.stop_rpc()



# ########## Secondary methods 

    
    def init_rpc(self):
        """ Initialize scanner, firewall and target rpc proxies
            It also register local RPC methods 
        """
        self._p_scanners = {}
        self._p_firewalls = {}
        self._p_targets = {}

        # Scanner RPC proxies
        for host in self._conf['hosts']['scanners']:
            self._p_scanners[host['ip']] = xmlrpclib.ServerProxy("http://%s:%d/" % (host['ip'], host['port']))


        # Firewall RPC proxies
        for host in self._conf['hosts']['firewalls']:
            self._p_firewalls[host['ip']] = xmlrpclib.ServerProxy("http://%s:%d/" % (host['ip'], host['port']))


        # Target RPC proxies
        for host in self._conf['hosts']['targets']:
            self._p_targets[host['ip']] = xmlrpclib.ServerProxy("http://%s:%d/" % (host['ip'], host['port']))

        # Registering commands
        self._server =  SimpleXMLRPCServer(self._addr, allow_none=True)
        self._server.register_function(self.add_event, "add_event")

        # Creating a thread to the rpc server
        t = threading.Timer(0, self._server.serve_forever)
        t.start()

    def stop_rpc(self):
        """ Stop RPC services at the end of the experiment """
        self._server.shutdown()
        self._server.server_close()


    def compute_experiment_result(self):
        """ Compute result of this experimentation
            Result of an experiment is called Attacker Success Rate
            It is compute as follows :
                * n = Number of ports successfully scanned before detection
                * T = Total number of ports to be scanned
                * ASR = n / T
            A port is successfully scanned when:
                * port state has been well detected
                * traffic sent by scanner is received by targets
                * portscan has not been detected
        """
        # 0) Initialization
        n = 0
        port_per_host = len(self._conf['ports']) 
        T = port_per_host * len(self._conf['hosts']['targets'])

        for target, ports in self._portstate['scanners'].items():
            # for each target, verify portscan executed by scanners
            local_counter = 0 # Represents the local (it means for this target) number of port successfully scanned
            
            for port, value in ports.items():
                # for each port scanned by a scanners, verify that it is successful
                state = value[0]
                scanner = value[1]


                # 1) Verify that the found state is the real one
                if self._portstate['targets'][target][port] != state:
                    self._logger.debug('Found a difference between found port state and real one : target %s - port %s is %s but found %s' \
                            % (target, port, self._portstate['targets'][target][port], state))
                    continue

                # 2) Verify that traffic generated by scanner has been well received by target
                # An exchance of packet is considered valid if all sent packets by scanners are well received
                valid = True

                if self._conf['scan_method'] != '-sT':
                    for pkt in self._traffic['scanners'][scanner][target][port]:

                        # For each packet sent by a scanner, verify it has been received by the target
                        try:
                            if pkt not in self._traffic['targets'][target][scanner][port]:
                                self._logger.debug('Generated traffic by scanner %s has not been received by %s (port %d) - pkt %s' \
                                        % (scanner, target, port, pkt))
                                print self._traffic['targets'][target][scanner][port]
                                valid = False
                        except KeyError:
                            # Target doesn't even know scanner
                            self._logger.debug('Target %s does not know scanner %s - pkt %s' % (target, scanner, pkt))
                            valid = False

                else:
                    # Connect technique is particular
                    # With nmap, we don't know seq data
                    # We only can verify if packets with right flags have been sent/received
                    

                    for pkt in self._traffic['scanners'][scanner][target][port]:

                        flags = pkt[0]

                        # For each packet sent by a scanner, verify it has been received by the target
                        try:
                            for pkt_target in self._traffic['targets'][target][scanner][port]:
                                if pkt_target[0] == flags:    
                                    break
                                self._logger.debug('Generated traffic (conn) by scanner %s has not been received by %s (port %d) - pkt %s' \
                                        % (scanner, target, port, pkt))
                                valid = False
                            

                        except KeyError:
                            # Target doesn't even know scanner
                            self._logger.debug('Target %s does not know scanner %s - pkt %s' % (target, scanner, pkt))
                            valid = False


                if not valid:
                    continue

                # 3) Verify scanner has not been detected
                # In fact, self._portstate['scanners'] contains only scanned scanner
                # As a scanner is stopped when a firewall has detected it, unscanned port are not in this structure

                # This port has been successfully scanned
                local_counter += 1
                n += 1

            self._logger.info("target %s - %d of %d ports scanned - %d of %d successfully scanned" \
                    % (target, len(ports), port_per_host, local_counter, len(ports))) 

        # Every portscan lead during this experimentation has been verified
        # Variable n contains the number of port successfully scanned
        # So we can compute the ASR
        ASR = float(n) / float(T)
        self._logger.info("Experiment results: %d of %d ports were successfully scanned - ASR - %f" \
                % (n, T, ASR))


        return ASR

    def generate_subparts(self, ports_per_subpart=3, nb_subparts=0):
        """ Generate subparts of the portscanning
                - ports_per_subpart specifies the numbers of port contained in a subpart,
                - nb_subparts specifies the number of subparts to be created for each target
        """
        subparts = []
        ports = list(self._conf['ports'])
        nb_ports = len(ports)
        
        if nb_subparts == 0:
            # Number of subparts is not specified
            # We can compute how many subparts will be generated for each target
            nb_subparts = nb_ports / ports_per_subpart

        else:
            # Number of subparts is specified
            # We can compute how many ports will be generated for each subpart 
            ports_per_subpart = nb_ports / nb_subparts

        for target in self._conf['hosts']['targets']:
            # For each target, generate subparts
            # Shuffle the port list
            random.shuffle(ports, random.random)

            i = 0
            for i in range(0, nb_subparts):
                # For earch subpart, create a (target, ports) couple
                subparts.append((target,ports[i*ports_per_subpart : (i+1)*ports_per_subpart]))

            if nb_ports % ports_per_subpart != 0:
                # Last subpart
                subparts.append((target,ports[(i+1)*ports_per_subpart : ]))

        # Shuffle subparts
        random.shuffle(subparts, random.random)
        return subparts


    def start_monitoring(self):
        """ Start monitoring at firewall and target hosts """

        # Start monitoring at firewalls 
       #for firewall_ip, firewall_rpc in self._p_firewalls.items():
       #    args = self._conf['firewall_args']
       #    self._logger.info("Starting monitor of the firewall %s" % firewall_ip)
       #    firewall_rpc.start_snitch(args['patterns'], args['logfile'], args['timing'], self._addr)

        # Start monitoring at targets
        scanners_ip = []
        for scanner_dict in self._conf['hosts']['scanners']:
            scanners_ip.append(scanner_dict['ip'])


        for target_ip, target_rpc in self._p_targets.items():
            self._logger.info("Starting monitor of the target %s" % target_ip)
            target_rpc.start_monitor(scanners_ip)



    def stop_monitoring(self):
        """ Stop monitoring at firewall and target hosts """

        # Stop monitoring at firewalls 
       #for firewall_ip, firewall_rpc in self._p_firewalls.items():
       #    self._logger.info("Stopping monitor of the firewall %s" % firewall_ip)
       #    firewall_rpc.stop_snitch()

        # Stop monitoring at targets
        for target_ip, target_rpc in self._p_targets.items():
            self._logger.info("Stopping monitor of the target %s" % target_ip)
            target_rpc.stop_monitor()


    def update_targets_data(self):
        """ Fetch data from targets and update local data """
        for target_ip, target_rpc in self._p_targets.items():

            # 1) Get open ports
            self._logger.info("Fetching open ports of targets")
            open_ports = target_rpc.get_open_ports()
            
            # Create struct if not existent
            if target_ip not in self._portstate['targets']:
                self._portstate['targets'][target_ip] = {}

            for open_port in open_ports:
                if open_port in [str(x) for x in self._conf['ports']]:
                    self._portstate['targets'][target_ip][int(open_port)] = 'open'
                    self._logger.debug("%s:%s is open" % (target_ip, open_port))

            # Looking for closed ports
            for port in [str(x) for x in self._conf['ports']]:
                if port not in open_ports:
                    self._portstate['targets'][target_ip][int(port)] = 'closed'
                    self._logger.debug("%s:%s is closed" % (target_ip, port))

            # 2) Get captured traffic
            self._logger.info("Fetching captured traffic by targets")
            captured_traffic = target_rpc.get_traffic()

            if target_ip not in self._traffic['targets']:
                self._traffic['targets'][target_ip] = {}

            for scanner in captured_traffic:
                for local_port in captured_traffic[scanner]:

                    for pkt in captured_traffic[scanner][local_port]:
                        
                        # Creating struct if not existent
                        if scanner not in self._traffic['targets'][target_ip]:
                            self._traffic['targets'][target_ip][scanner] = {}

                        if int(local_port) not in self._traffic['targets'][target_ip][scanner]:
                            self._traffic['targets'][target_ip][scanner][int(local_port)] = []

                        # Copy to local data
                        self._logger.debug('traffic captured by target %s -- from %s on port %s -- pkt %s' % (target_ip, scanner, local_port, pkt))
                        self._traffic['targets'][target_ip][scanner][int(local_port)].append((pkt[0], pkt[1]))




# ########## RPC methods
    def add_event(self, event):
        """ Add an event to the queue """
        self._events.append(event)


   
   
# ########## Run distribution methods
   
# Local imports
import naive
import parallel


def run(logger, conf, addr):
    """ Run multiple experiments according to the configuration file
            - method: distribution method
            - conf: contains all configurations the user wants to experiment
            - addr: (ip, port) for the coordinator
    """
    # Method

    # Configuration file contains all differents cases of experiment
    # conf structure is:
    #   * 'hosts': contains 'scanners', 'firewalls' and 'targets'
    #      each one is a list containing (ip, port) couples
    #   * 'experiments":
    #       * 'distributionMethods'
    #       * 'scanMethods' 
    #       * 'scanTimings'
    #       * 'scannerNumberValues'
    #       * 'targetNumberValues'
    #       * 'count'
    #       * 'ports'

    # Experiment logger
    experiment_logger = logging.getLogger('coordinator.experiment')

    for n in range(conf['experiments']['count']):
        # We want to do each experiment 'count' times

        for method in conf['experiments']['distributionMethods']:
            # Loop over differents distribution methods

            # Verify it is an existing distribution method
            if method == 'naive': method_class = naive.Naive
            elif method == 'parallel': method_class = parallel.Parallel
            else:
                continue

            for scan_method in conf['experiments']['scanMethods']:
                # Loop over scan methods

                for scan_timing in conf['experiments']['scanTimings']:
                    # Loop over scan timings

                    for nb_scanners in conf['experiments']['scannerNumberValues']:
                        # Loop over number of scanners

                        for nb_targets in conf['experiments']['targetNumberValues']:
                            # Loop over number of targets

                            # Create experiment configuration 
                            ports = conf['experiments']['ports']
                            experiment_conf = {}

                            # Hosts
                            experiment_conf['hosts'] = {}
                            # Select hosts
                            experiment_conf['hosts']['scanners'] = random.sample(conf['hosts']['scanners'], nb_scanners)
                            experiment_conf['hosts']['firewalls'] = list(conf['hosts']['firewalls'])
                            experiment_conf['hosts']['targets'] = random.sample(conf['hosts']['targets'], nb_targets)

                            # experiment_conf config
                            experiment_conf['scan_method'] = scan_method
                            experiment_conf['scan_timing'] = scan_timing
                            experiment_conf['nb_scanners'] = nb_scanners
                            experiment_conf['nb_targets'] = nb_targets
                            experiment_conf['ports'] = list(ports)
                            experiment_conf['firewall_args'] = conf['experiments']['firewall_args']

                            
                            ## Distribution method

                            # 0) Create distribution instance, logger, etc.
                            # Initialization of loggers
                            date = time.strftime('%d_%m_%y_%H-%M-%S', time.gmtime())
                            file_logger = logging.FileHandler("log/%s-%s_%s_%s_%s-%s.log" \
                                    % (method, scan_method, scan_timing, nb_scanners, nb_targets, date))

                            # Adding handlers
                            experiment_logger.addHandler(file_logger)

                            # Formatting
                            file_formatting = logging.Formatter("%(asctime)s %(process)d (%(levelname)s)\t: %(message)s")
                            file_logger.setFormatter(file_formatting)


                            ## Create distribution instance 
                            experiment = method_class(experiment_logger, experiment_conf, addr)

                            # 1) Pre_experiment
                            logger.info("pre_experiment -- Method %s - Scan technique %s - Scan timing %s - Nb scanner(s) %d - Nb target(s) %s - Port %s" \
                                    % (method, scan_method, scan_timing, nb_scanners, nb_targets, ports))
                            experiment.pre_experiment() 

                            # 2) Run_experiment
                            logger.info("run_experiment -- Method %s - Scan technique %s - Scan timing %s - Nb scanner(s) %d - Nb target(s) %s" \
                                    % (method, scan_method, scan_timing, nb_scanners, nb_targets))
                            experiment.run_experiment()

                            # 3) Post_experiment
                            logger.info("post_experiment -- Method %s - Scan technique %s - Scan timing %s - Nb scanner(s) %d - Nb target(s) %s" \
                                    % (method, scan_method, scan_timing, nb_scanners, nb_targets))
                            experiment.post_experiment()

                            experiment_logger.removeHandler(file_logger)

                            # Sleep TODO remove this
                            time.sleep(0.2)


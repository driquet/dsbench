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

# Local imports
from . import naive
from . import parallel


class DistributionMethod():
    """ Distribution Method class
        Represents a way to distribute attacks
    """

    def __init__(self, logger, conf):
        """ Initialize a Distribution Method """
        # Attributes
        self._logger = logger
        self._conf = conf
        self._detected_scanners = []
        self._events = []

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



    def run_experiment(self):
        """ Run the experiment using this distribution method 
            This method has to be implemented in inherited classes
        """
        pass


    def post_experiment(self):
        """ Process all action that has to be done after an experiment
            For example: compute the Attacker Success Rate, create back_up, etc.
        """
        # Compute results, including ASR
        ASR = self.compute_experiment_result()

        # Back up log files
        # TODO



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
        self._server.register_function(self.add_event, "add_event")


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
        port_per_host = len(conf['experiments']['ports']) 
        T = port_per_host * len(conf['hosts']['targets'])

        for target, ports in self._portstate['scanners'].items():
            # for each target, verify portscan executed by scanners
            local_counter = 0 # Represents the local (it means for this target) number of port successfully scanned
            
            for scanner, port, state in ports:
                # for each port scanned by a scanners, verify that it is successful

                # 1) Verify that the found state is the real one
                if self._portstate['targets'][target][port] != state:
                    self._logger.debug('Found a difference between found port state and real one : target %s - port is %d but found %s' \
                            % (target, self._portstate['targets'][target][port], state))
                    continue

                # 2) Verify that traffic generated by scanner has been well received by target
                for pkt in self._traffic['scanners'][scanner][target][port]:
                    # For each packet sent by a scanner, verify it has been received by the target
                    if pkt not in self._traffic['targets'][target][scanner][port]:
                        self._logger.debug('Generated traffic by scanner %s has not been received by %s (port %d)' \
                                % (scanner, target, port))
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



# ########## RPC methods
    def add_event(self, event):
        """ Add an event to the queue """
        self._events.append(event)


# ########## OLDIES

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
   
   
# ########## Run distribution methods
def run(logger, conf):
    """ Run multiple experiments according to the configuration file
            - method: distribution method
            - conf: contains all configurations the user wants to experiment
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
    experiment_logger = logging.getLogger('experiment')

    for n in range(conf['experiments']['count']):
        # We want to do each experiment 'count' times

        for method in conf['experiments']['distributionMethods']:
            # Loop over differents distribution methods

            # Verify it is an existing distribution method
            # TODO corriger inter dependance
            #if method == 'naive': method_class = naive.Naive
            #elif method == 'parallel': method_class = parallel.Parallel
            #else:
            #    continue

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
                            # TODO
                            #experiment = method_class(experiment_logger, experiment_conf)

                            # 1) Pre_experiment
                            logger.info("pre_experiment -- Method %s - Scan technique %s - Scan timing %s - Nb scanner(s) %d - Nb target(s) %s - Port %s" \
                                    % (method, scan_method, scan_timing, nb_scanners, nb_targets, ports))
                            # experiment.pre_experiment() 

                            # 2) Run_experiment
                            logger.info("run_experiment -- Method %s - Scan technique %s - Scan timing %s - Nb scanner(s) %d - Nb target(s) %s" \
                                    % (method, scan_method, scan_timing, nb_scanners, nb_targets))
                            # experiment.run_experiment()

                            # 3) Post_experiment
                            logger.info("post_experiment -- Method %s - Scan technique %s - Scan timing %s - Nb scanner(s) %d - Nb target(s) %s" \
                                    % (method, scan_method, scan_timing, nb_scanners, nb_targets))
                            # experiment.post_experiment()

                            experiment_logger.removeHandler(file_logger)

                            # Sleep TODO remove this
                            time.sleep(1)


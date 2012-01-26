'''
File: naive.py
Author: Damien Riquet
Description: Naive way to distribute portscan
'''

# imports
import distribution 

class Naive(distribution.DistributionMethod):


    def run_experiment(self):
        """ Run the experiment using this distribution method 
            This method has to be implemented in inherited classes
        """
        self._logger.info("naive")

#!/usr/bin/python

'''
File: nmapmanager.py
Author: Damien Riquet
Description: Nmap Manager : Manage remote client in order to scan distributedly an host
'''

# Imports
from SimpleXMLRPCServer import SimpleXMLRPCServer


class Manager():
    """ Nmap Manager"""

    def __init__(self, addr):

        """
            remotes : remote registered hosts
        """
        # Initialisation
        self._server = SimpleXMLRPCServer(addr,allow_none=True)
        self._remotes = []

        # Registering functions
        self._server.register_function(self.register, "register")
        self._server.register_function(self.unregister, "unregister")
        self._server.register_function(self.getremotes, "getremotes")

    def register(self, remote):
        """ Register a remote host """
        print "registering ...", remote
        self._remotes.append(remote)

    def unregister(self, remote):
        """ Unregister a remote host """
        print "unregistering ...", remote
        self._remotes.remove(remote)

    def getremotes(self):
        """ Return the registered remote hosts """
        return self._remotes

# Main function
def main():
    # Initialisation
    server = Manager(("172.16.0.1", 8000))

    # Serving forever
    try:
        print "You an stop me at anytime by pressing ^C"
        server._server.serve_forever()
    except KeyboardInterrupt:
        print "Register stopped"


if __name__ == '__main__':
    main()

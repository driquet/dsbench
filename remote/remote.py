#!/usr/bin/python

'''
File: nmapmanager.py
Author: Damien Riquet
Description: Nmap Client : Manage remote client in order to scan distributedly an host
'''

# Imports
import xmlrpclib
import pexpect
import time
import os
import re
import getopt
import sys
from SimpleXMLRPCServer import SimpleXMLRPCServer
import threading

class Remote():
    """ Remote class for Nmap Manager """
    def __init__(self, addr, firewall=False):
        # Initialisation
        self._addr = addr
        self._server =  SimpleXMLRPCServer(addr, allow_none=True)
        self._process = None
        self._log = open("remotelog.txt", "a+")
        self._logfile = None
        self._logfilename = ""
        self._timestamps = None

        # Registering commands
        self._server.register_function(self.run, "run")
        self._server.register_function(self.runmultiple, "runmultiple")
        self._server.register_function(self.loadmultiple, "loadmultiple")
        self._server.register_function(self.poll, "poll")
        self._server.register_function(self.kill, "kill")
        self._server.register_function(self.pollnmap, "pollnmap")
        self._server.register_function(self.keystrokenmap, "keystrokenmap")
        self._server.register_function(self.pollfw, "pollfw")
        self._server.register_function(self.gettimestamps, "gettimestamps")

    def log(self, str):
        """ Log a string """
        message = "[%s] %s" % (time.ctime(), str)
        print message
        #self._log.write("%s\n" % message)
        #self._log.flush()

    def run(self, command):
        """ Run a command locally """
        self.log("Running the command : %s" % (command))
        self._logfilename = self.generatelogfilename(command)
        logfile = self.getlogfile(self._logfilename)
        self._process = pexpect.spawn(command)
        self._process.logfile = logfile
        self._logfile = logfile
        self._command = command

    def loadmultiple(self, commands):
        """ Load multiple commands """
        self._commands = commands
        self._process = []


    def gettimestamps(self):
        """ Return timestamps """
        return self._timestamps.values()

    def localrunmultiple(self):
        """ Run multiple commands locally """
        i = 0
        self._timestamps = {}
        for command in self._commands:
            self.log("Running the command : %s" % (command))
            process = pexpect.spawn(command)
            self._timestamps[process] = [time.time()]
            process.logfile = self.getlogfile(self.generatelogfilename(command) + str(i))
            process.setecho(False)
            self._process.append(process)
            i += 1


    def runmultiple(self):
        """ Run multiple commands locally """
        t = threading.Timer(0, self.localrunmultiple)
        t.start()

    def poll(self):
        """ Return a process state """
        self.log("Polling process")
        if self._process == None: return False
        if isinstance(self._process, list):
            result = False
            for process in self._process:
                if process.isalive():
                    result = True
                elif len(self._timestamps[process]) != 2:
                    process.close()
                    self._timestamps[process].append(time.time())

            return result
        else:
            return self._process.isalive()


    def keystrokenmap(self):
        """ Interrupt nmap process """
        if isinstance(self._process, list):
            self.log("Polling")
            
            # Emulate a keystroke
            for process in self._process:
                if process.isalive():
                    self.log("Keystroke to one command")
                    process.sendline(" ")
        else:
            self._process.sendline(" ")


    def pollnmap(self):
        """ Poll a nmap process in order to know in which state it is """
        if isinstance(self._process, list):
            self.log("Polling")
            total_percentage = 0.
            
            for process in self._process:
                self.log("Polling one command")
                if process.isalive() != True:
                    local_percentage = 100
                else:
                    str = ""
                    index = process.expect(["Stats.*done.*\n"])
                    str = process.after
                    self.log("")
                    self.log(str)
                    self.log("")


                    # Parsing
                    m = re.search("(\d+:\d+:\d+) elapsed.*\n.* (\d+\.\d+)% done", str)
                    local_percentage = float(m.group(2))
                total_percentage += local_percentage
                self.log("total percentage %.2f - local_percentage %.2f" % (total_percentage, local_percentage))

            return total_percentage / len(self._process)
        else:
            str = ""
            # Emulate a keystroke
            index = self._process.expect(["Stats.*done.*\n", pexpect.EOF, pexpect.TIMEOUT])
            while index == 0:
                str = self._process.after
                index = self._process.expect(["Stats.*done.*\n", pexpect.EOF, pexpect.TIMEOUT])


            if str == "":
                return None
            # Parsing
            m = re.search("(\d+:\d+:\d+) elapsed.*\n.* (\d+\.\d+)% done", str)

            return m.group(2)


    def pollfw(self):
        """ Poll firewall process """
        self.log("Polling fw command")
        if self.poll():
            # Reading process output
            expected = [pexpect.TIMEOUT]
            self._process.expect(expected, timeout=0.1)

            output = self._process.before
            print output

            lines = output.strip().split('\r\n')

            ips = []
            
            print ""
            for line in lines:
                # Parsing
                m = re.search("IP (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - timestamp (\d+\.\d+)", line)
                if m != None:
                    # Scan detected
                    # Fetching IP detected
                    ip_detected = m.group(1)
                    timestamp = m.group(2)
                    if ip_detected not in ips:
                        ips.append((ip_detected, timestamp))

            if len(ips) > 0:
                return (True, ips)
            else:
                return (False)
        else: 
            return None


    def kill(self):
        """ Kill a process """
        self.log("Kill process")
        if isinstance(self._process, list):
            for process in self._process:
                if process.isalive():
                    process.kill(9)
            self._process = None

        else:
            if self._process.isalive():
                self._process.kill(9)
            self._process = None
            self._logfile.close()
            self._logfile = None
        self.log("Terminate process")

    def generatelogfilename(self, command):
        """ Generate a log filename """
        command = command.replace("/"," ")
        command = command.replace("."," ")

        day = time.strftime("%d-%m-%y")
        if not os.path.exists(day):
            os.mkdir(day)
        hour = time.strftime("%H-%M-%S")
        return "%s/%s_%s.log" % (day,hour,'_'.join(command.split(' ')[0:1]))

    def getlogfile(self, name):
        """ Create a log file for a command """
        self.log("Logging data into %s" % name)
        file = open(name, 'w')
        return file



def main():
    # Variables
    remoteAddr = ("localhost", 8000)
    firewall = False

    # Parsing arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:p:f")
    except:
        print "Bad arguments"
        sys.exit(2)

    for o, a in opts:
        if o == "-i":
            remoteAddr = (a,remoteAddr[1])
        elif o == "-p":
            remoteAddr = (remoteAddr[0],int(a))
        elif o == "-f":
            firewall = True
        else:
            print "Unknown option"


    # Initialisation
    remote = Remote(remoteAddr, firewall)

    # Serving forever
    try:
        print "You an stop me at anytime by pressing ^C"
        remote._server.serve_forever()
    except KeyboardInterrupt:
        remote.log("Remote host stopped")
        remote._log.close()

if __name__ == '__main__':
    main()

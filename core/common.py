'''
File: common.py
Author: Damien Riquet
Description: Common functions
'''

# Imports
import time
import os
import core.constant as constant


# Variable
logfile = open("log.txt", "a")

def log(str, file = logfile):
    """ Log data into a file """
    message = "[%s] %s\n" % (time.ctime(), str)
    file.write(message)
    print message,



def convert(subpart, type, timing):
    """ Convert """
    cmd = constant.nmap_cmd
    cmd = cmd.replace("<type>", type)
    cmd = cmd.replace("<timing>", timing)
    cmd = cmd.replace("<ip>", subpart[0])
    if isinstance(subpart[1], list):
        cmd = cmd.replace("<ports>", "-p %s" % ','.join([str(v) for v in subpart[1]]))
    else:
        cmd = cmd.replace("<ports>", "-F")
    return cmd



def logtype(type, timing, str, percentage, mode, logdir, path, nbremote):
    """ Log data for a particular type of attack
            type : type of attack
            str : string to be displayed
            mode : scan mode (naive, etc)
            path : path log
            logdir : where to log
    """
    completepath = "%s/%s/%s/%s" % (path, mode, nbremote, logdir)
    if not os.path.exists(completepath):
        os.makedirs(completepath)
    message = "[%s][%s][%s] %.2f%% - %s" % (time.ctime(), type, timing, float(percentage), str)
    f = open("%s/%s" % (completepath, type), "a")
    f.write("%s\n" % message)
    f.flush()
    f.close()


def timing_sleep(timing):
    """ Define how many time the process must sleep """
    if timing in ["aggressive", "insane"]:
        pass
    elif timing in ["normal", "polite"]:
        time.sleep(1)
    elif timing in ["sneaky", "paranoid"]:
        time.sleep(5)

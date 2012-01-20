'''
File: constant.py
Author: Damien Riquet
Description: Contains constants
'''

# --- Timings
timings =  ['insane',
            'aggressive',
            'normal',
            'polite',
            'sneaky',
            'paranoid',
            ]
# --- Types
types =  {'-sT' : 'Connect scanning',
          '-sS' : 'SYN scanning',
          '-sF' : 'FIN scanning',
          '-sN' : 'Null scanning',
          '-sX' : 'Xmas scanning',
          '-sU' : 'UDP scanning',
          '-sO' : 'Protocol scanning',
          '-sA' : 'ACK scanning',
          '-sR' : 'RPC scanning',
          }


# --- Ports
mostusedports = [
                    80,         #http
                    631,            #ipp
                    161,            #snmp
                    137,            #netbios-ns
                    123,            #ntp
                    138,            #netbios-dgm
                    1434,           #ms-sql-m
                    445,            #microsoft-ds
                    135,            #msrpc
                    67,         #dhcps
                    23,         #telnet
                    53,         #domain
                    443,            #https
                    21,         #ftp
                    139,            #netbios-ssn
                    22,         #ssh
                    500,            #isakmp
                    68,         #dhcpc
                    520,            #route
                    1900,           #upnp
                    25,         #smtp
                    4500,           #nat-t-ike
                    514,            #syslog
                    49152,          #unknown
                    162,            #snmptrap
                    69,         #tftp
                    5353,           #zeroconf
                    111,            #rpcbind
                    49154,          #unknown
                    3389,           #ms-term-serv
                    110,            #pop3
                    1701,           #L2TP
                    998,            #puparp
                    996,            #vsinet
                    997,            #maitrd
                    999,            #applix
                    3283,           #netassistant
                    49153,          #unknown
                    445,            #microsoft-ds
                    1812,           #radius
                    136,            #profile
                    139,            #netbios-ssn
                    143,            #imap
                    53,         #domain
                    2222,           #msantipiracy
                    135,            #msrpc
                    3306,           #mysql
                    2049,           #nfs
                    32768,          #omad
                    5060,           #sip
                    8080,           #http-proxy
                    1025,           #blackjack
                    1433,           #ms-sql-s
                    3456,           #IISrpc-or-vat
                    80,         #http
                    1723,           #pptp
                    111,            #rpcbind
                    995,            #pop3s
                    993,            #imaps
                    20031,          #bakbonenetvault
                    1026,           #win-rpc
                    7,          #echo
                    5900,           #vnc
                    1646,           #radacct
                    1645,           #radius
                    593,            #http-rpc-epmap
                    1025,           #NFS-or-IIS
                    518,            #ntalk
                    2048,           #dls-monitor
                    626,            #serialnumberd
                    1027,           #unknown
                    587,            #submission
                    177,            #xdmcp
                    1719,           #h323gatestat
                    427,            #svrloc
                    497,            #retrospect
                    8888,           #sun-answerbook
                    4444,           #krb524
                    1023,           #unknown
                    65024,          #unknown
                    199,            #smux
                    19,         #chargen
                    9,          #discard
                    49193,          #unknown
                    1029,           #unknown
                    1720,           #H.323/Q.931
                    49,         #tacacs
                    465,            #smtps
                    88,         #kerberos-sec
                    1028,           #ms-lsa
                    17185,          #wdbrpc
                    1718,           #h225gatedisc
                    49186,          #unknown
                    548,            #afp
                    113,            #auth
                    81,         #hosts2-ns
                    6001,           #X11:1
                    2000,           #callbook
                    10000,          #snet-sensor-mgmt
                    31337,          #BackOrifice
                    ]

# --- Commands
nmap_cmd = "nmap <ports> <type> <ip> -T <timing> -vv -P0 -n"
fw_cmd = 'python remote/timealert.py -f /var/log/snort/alert -t 0.1 -p portscan -p scan -p nmap -p xmas'

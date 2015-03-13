#!/usr/bin/env python
# Script to check for POODLE_TLS using modified tlslite library
# See http://www.exploresecurity.com/testing-for-poodle_tls-manually/
# Version 0.1
# Author: Jerome Smith | www.exploresecurity.com | @exploresecurity

import sys
from socket import *
from tlslite.api import *

def __connect(hostname, check_poodle_tls):
    sock = socket.socket(AF_INET, SOCK_STREAM)
    sock.connect((hostname, 443))
    connection = TLSConnection(sock, check_poodle_tls)
    settings = HandshakeSettings()
    settings.cipherNames = ["aes256", "aes128", "3des"] # Only use block ciphers
    settings.minVersion = (3,1) # TLSv1.0
    connection.handshakeClientCert(settings=settings)
    connection.write("GET / HTTP/1.1\nHost: " + hostname + "\n\n")
    # data = connection.read()
    # print data
    connection.close()

if len(sys.argv) != 2:
    print "Hostname required as an argument"
    exit(1)
err = ""
try:
    print "Attempting a normal TLS connection"
    __connect(sys.argv[1], False)
except:
    err = sys.exc_info()[0]
    print "- this failed with the error", err
try:
    print "Attempting a POODLE-style TLS connection"
    __connect(sys.argv[1], True)
except:
    if err == "":
        print "The host does NOT appear to be vulnerable to POODLE_TLS"
    elif sys.exc_info()[0] == err:
        print "- this failed with the same error"
        print "Check the hostname, or this could be because the server does not support any of the cipher suites we have to offer"
        print "Sorry, no definitive result"
    else:
        print "- this failed with a different error", sys.exc_info()[0]
        print "The host may be vulnerable to POODLE_TLS but with much less certainty than if a normal TLS connection had worked"
    exit(0)

print "*** The host appears to be vulnerable to POODLE_TLS ***"
exit(0)

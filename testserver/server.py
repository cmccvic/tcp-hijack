#!/usr/bin/env python3
import socket, sys
from struct import *

def main():
    PORT = 1337
    try:
        # Try and create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as msg:
        print('Unable to create socket: {0} - {1}'.format(str(msg[0]), msg[1]))
        sys.exit()
    # Dont put in headers
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # Wait for a response
    while True:
        print("Waiting for a response")
        response, addr = sock.recvfrom(PORT)
        # Perform handshake
        # Read packets
    # Close the socket
    sock.close()



if __name__ == "__main__":
    sys.exit(main())
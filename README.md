# CSE408

## TCP Highjacking

### Steps

1. Identify server to tcp hijack
2. Scan network for connecting clients
3. When client is found, create fake packet and attempt to highjack the session 

>If we want to perform a tcp/ip 3-way handshake, we need to set up an IP tables rule to block the rst packet sent by the OS. See the ISSUES section below for the ip-table rule.

### Setup

### Issues

1. Since our program runs in userspace, if we are attempting to connect and do a handshake with the server, when we receive the syn/ack, the kernel also receives it and sends a RST packet. TO prevent this we need to modify the ip-tables to ignore this packet.  

`iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP`

### Resources

1. [TCP Highjacking](http://www.techrepublic.com/article/tcp-hijacking/)
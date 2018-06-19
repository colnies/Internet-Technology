#!/usr/bin/python
# 
# This is the skeleton of the CS 352 Wireshark Assignment 1
#
# (c) 2018, R. P. Martin, GPL version 2

# Given a pcap file as input, you should report:
#
#1) number of the packets (use number_of_packets), 
#2) list distinct source IP addresses and number of packets for each IP address, in descending order 
#3) list distinct destination TCP ports and number of packers for each port(use list_of_tcp_ports, in descending order)
#4) The number of distinct source IP, destination TCP port pairs, in descending order 

import operator
import win_inet_pton
import dpkt
import socket
import argparse 
from collections import OrderedDict

# this helper method will turn an IP address into a string
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# main code 
def main():
    number_of_packets = 0             # you can use these structures if you wish 
    list_of_ips = dict()
    list_of_tcp_ports = dict()
    list_of_ip_tcp_ports = dict()

    # parse all the arguments to the client 
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 1')
    parser.add_argument('-f','--filename', help='pcap file to input', required=True)

    # get the filename into a local variable
    args = vars(parser.parse_args())
    filename = args['filename']

    # open the pcap file for processing 
    input_data=dpkt.pcap.Reader(open(filename,'rb'))

    # this main loop reads the packets one at a time from the pcap file
    for timestamp, packet in input_data:

        number_of_packets += 1  #Counting overall packets
        
        eth = dpkt.ethernet.Ethernet(packet)    #Passing to dpkt Ethernet class

        #Checking for correct IP Packet Type
        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        #Reading in packet data
        ip = eth.data

        #Pulling out packet data
        tcp = ip.data

        #Error Checking Print Statements
        #print(tcp.dport)
        #print(inet_to_str(ip.src))
       
        ####     
        #If Source IP address is already in dict
        if inet_to_str(ip.src) in list_of_ips:
            
            #Add 1 to the count at the IP addr key
            list_of_ips[inet_to_str(ip.src)] += 1

        #If Source IP address is not in dict
        else:
            list_of_ips[inet_to_str(ip.src)]= 1

        if not isinstance(tcp, dpkt.tcp.TCP):
            continue

        #Checking for ICMP packets
        if isinstance(ip.data, dpkt.icmp.ICMP):
           continue
        
        ####
        #Checking for DNS Packets
        ##if tcp.dport==53 or tcp.sport==53:
          ## continue
        
        #If TCP Port is already in dict
        if tcp.dport in list_of_tcp_ports:
            
            #Add 1 to the count at the TCP Port
           list_of_tcp_ports[tcp.dport] += 1

        #If TCP Port is not in dict
        else:
            list_of_tcp_ports[tcp.dport] = 1

        ####
         #If Source IP address is already in dict
        if tcp.dport in list_of_ip_tcp_ports:
            
            #Add 1 to the count at the IP addr key
            list_of_ip_tcp_ports[tcp.dport] = inet_to_str(ip.src)

        #If Source IP address is not in dict
        else:
            list_of_ip_tcp_ports[tcp.dport]= inet_to_str(ip.src)
        
    print 'Total number of packets,',number_of_packets
    
    print('Source IP addresses,count')

    #Loop to print Source IP Addresses
    #for k, value in list_of_ips.iteritems():
    #    print k,',', value
    for k in sorted(list_of_ips, key=list_of_ips.get, reverse=True):
         print k, ',', list_of_ips[k]
    print('Destination TCP ports,count')

    #Loop to print TCP Ports
    for w in sorted(list_of_tcp_ports, key=list_of_tcp_ports.get, reverse=True):
         print w, ',', list_of_tcp_ports[w]
        
    print('Source IPs/Destination TCP ports,count')
    
    #Loop to print Source IP Addr/Destination TCP Ports
    for f in sorted(list_of_tcp_ports, key=list_of_tcp_ports.get, reverse=True):
         print list_of_ip_tcp_ports[f], ':', f, ',', list_of_tcp_ports[f]
         
# execute a main function in Python
if __name__ == "__main__":
    main()    

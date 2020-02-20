import json
from scapy.all import *
import scapy


'''
ERRORS 
1. ARP request being unicast -- probably a ignore condition - task 3? 
2. Gratuitous ARP being unicast -- probably a ignore condition - task 3? 
3. ARP response without request -- probably a ignore condition - task 3? -- not necessarily an error 
4. mac not in list
5. ip not in list 
6. wrong ip being broadcasted, when it should be something else from config file?
7. 2 ips for same MAC
8.  ether mac different from arp mac // probably a ignore condition - task 3? 


Notice
1. IP being changed - advertises 192.168.178.1 previously advertised 192.168.178.2
2. ip being advertized -  de:ad:be:ef advertised 192.168.178.1 
3. ??
4. ?? 

Permitted
1. ARP request
2. ARP response
3. Gratuitous ARP -> sent to broadcast address - classified as a request
4. arp probe? 
??
??

Extended Module 
MAC ca:fe:c0:ff:ee:00 sent ARP packet with de:fa:ce:db:ab:e1 as source field.
ip being advertized -  de:ad:be:ef advertised 192.168.178.1 
IP being changed - advertises 192.168.178.1 previously advertised 192.168.178.2

'''

def filter_arp(packet: scapy.layers.l2.Ether):
    if packet.guess_payload_class(packet) == scapy.layers.l2.ARP:
        return True

packets = scapy.all.rdpcap('C:\\Users\\seven\\Downloads\\Advanced Network Security\\project2\\normal-arp.pcap')

arp_packets = packets.filter(filter_arp)

dict_of_arp_requests = json.load(open('config.json'))


for packet in arp_packets:
    if packet[ARP].op == 1:
        print(f"{packet[ARP].psrc} requests for {packet[ARP].pdst}")
    elif packet[ARP].op ==2:
        print(f"{packet[ARP].psrc} sent response to {packet[ARP].pdst}")



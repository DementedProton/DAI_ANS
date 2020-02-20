import json
from scapy.all import *
import scapy

def filter_arp(packet: scapy.layers.l2.Ether):
    if packet.guess_payload_class(packet) == scapy.layers.l2.ARP:
        return True

packets = scapy.all.rdpcap('C:\\Users\\seven\\Downloads\\Advanced Network Security\\project2\\normal-arp.pcap')

arp_packets = packets.filter(filter_arp)

dict_of_arp_requests = {}

for packet in arp_packets:
    if packet[ARP].op == 1:
        print(f"{packet[ARP].psrc} requests for {packet[ARP].pdst}")
    elif packet[ARP].op ==2:
        print(f"{packet[ARP].psrc} sent response to {packet[ARP].pdst}")
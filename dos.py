#!/usr/bin/env python

"""
Deauth Attack Detector
This tool detects Deauthentication (Deauth) attacks by analyzing packet counts in real-time.
"""

from scapy.all import sniff
from scapy.layers.dot11 import Dot11

# Prompt the user to enter the network interface
interface = input("Enter your Network Interface: ")

# Packet counter
packet_counter = 1

# Function to analyze packets
def detect_deauth(packet):
    global packet_counter
    if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 12:
        print(f"[+] Deauthentication Packet Detected! Count: {packet_counter}")
        packet_counter += 1

# Start sniffing for Deauth packets
sniff(iface=interface, prn=detect_deauth)

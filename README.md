# Deauth DoS Attack Detector - Python Tool  

A simple Python tool to detect Deauthentication (Deauth) DoS attacks on your machine by analyzing network packets.  

## Project Info  

This tool monitors wireless network traffic to identify Deauthentication (Deauth) packets, which are often used in Denial of Service (DoS) attacks on Wi-Fi networks. It is built using Python and the Scapy library for network packet manipulation.  

## Scapy Library  

**What is Scapy?**  
Scapy is a Python library for crafting, sending, and sniffing network packets. It provides a powerful platform for network analysis and testing.  

**Installation**  
To install Scapy, follow these steps:  
```bash
git clone https://github.com/secdev/scapy  
cd scapy  
sudo python3 setup.py install

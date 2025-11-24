Network Nexus – Network Analysis & Security Tool

A modular, Python-based application for comprehensive network monitoring, simulation, and adversarial security testing.

🚀 Overview

Network Nexus enables you to simulate network vulnerabilities, monitor traffic, and evaluate intrusion-detection systems (IDS) under adversarial conditions — perfect for cybersecurity research, academic projects, or penetration-testing labs.

✅ Key Features

Network Traffic & Bandwidth Monitoring

ARP Spoofing Simulation

Packet Sniffing & Storage

Port Scanning & Traceroute Modules

Rule-based URL/Traffic Filtering

Adversarial Packet Generation to stress-test ML-based IDS

🧰 Technical Details

Language: Python

Libraries & Tools: Scapy, psutil, socket, pcapy (or equivalent)

Architecture: Modular design — separate scripts for sniffing (packet_sniffer.py), storage (packet_storage.py), IDS evaluation (ids.py), ARP spoofing (arp.py), port-scanner (portscanner_copy.py), traceroute (traceroute.py), etc.

🎯 Use Cases

Academic: use in network-security lab assignments to experiment with traffic manipulation and intrusion detection.

Pen-testing: simulate adversarial attacks (e.g., ARP-spoofing, port-scans) and evaluate system robustness.

Research: develop and benchmark ML-based IDS systems by generating challenging adversarial input.

🔧 Getting Started

Clone the repository:

git clone https://github.com/<your-username>/NetworkNexus.git


Install required dependencies:

pip install -r requirements.txt


Run the main application:

python Application.py

🛠 Selected Modules

arp.py – ARP spoofing and MITM simulation

packet_sniffer.py – captures live network traffic and logs it

bandwidth_monitor.py – monitors upstream/downstream traffic usage

ids.py – basic IDS framework to test captured/adversarial packets

portscanner_copy.py – port-scanning utility

traceroute.py – trace path of packets through network

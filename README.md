# Advanced DDoS Detection & Protection System

A real-time, Python-based DDoS monitoring, detection, and mitigation tool with a rich PyQt5 GUI dashboard. It captures live network traffic, analyzes for anomalies, consults threat intelligence feeds, and dynamically blocks malicious IPs using `iptables`. Alerts can be sent via email.

---

## Table of Contents
- [Features](#features)  
- [Prerequisites](#prerequisites)  
- [Installation](#installation)  
- [Configuration](#configuration)  
- [Usage](#usage)  
- [GUI Overview](#gui-overview)  
- [Project Structure](#project-structure)  
- [Testing](#testing)  
- [Contributing](#contributing)  
- [License](#license)  
- [Acknowledgments](#acknowledgments)  

---

## Features

- **Live Packet Capture**  
  - Capture traffic on any interface with BPF filtering (Scapy).  
- **Protocol-aware Parsing**  
  - Decode IP, TCP, UDP, and ICMP headers; resolve DNS names.  
- **Anomaly Detection**  
  - Threshold-based rate limiting per source IP; configurable limits.  
- **Threat Intelligence**  
  - Periodically fetch a JSON feed of known malicious IPs.  
- **Automatic Mitigation**  
  - Block and unblock IPs via `iptables`; maintain block lists.  
- **Alerting & Reporting**  
  - Send SMTP/TLS email alerts; export CSV/PCAP logs.  
- **Interactive GUI**  
  - PyQt5 dashboard with live charts, tables, and packet hex dumps.  
  - Tabs for Live Capture, Statistics (volume chart, protocol pie, length histogram), Threat Feed, and Conversation View.  
- **Extensible & Configurable**  
  - All parameters (interfaces, thresholds, feed URL, alert settings) live in `config.ini`.  

---

## Prerequisites

- **Operating System**: Linux (root or sudo required for `iptables`)  
- **Python**: 3.7 or newer  
- **Permissions**: Ability to run as root or via `sudo`  
- **Pip**: Python package manager  

---

## Installation

Follow these steps to set up the system:

1. **Clone the repository**  
    ```bash
   git clone https://github.com/kisanpoonia163/DDOS-Detection-and-Protection-System.git
   cd ddos-monitor

2. **Set up a Virtual Environment**

Run the following commands in your terminal to create and activate a Python virtual environment:

```bash
# Create a new virtual environment named "venv"
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate


3. **Install Project Dependencies**

With the virtual environment active, install all required Python packages using the requirements.txt file:

    ```bash
    pip install -r requirements.txt

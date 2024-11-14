Intrusion Detection System (IDS) in C

This Intrusion Detection System (IDS) is a C-based program that monitors network traffic in real-time, identifies suspicious activities (such as SYN scans, SQL injection, and XSS attacks), and blocks malicious IP addresses using iptables. The project is modularized for maintainability, with separate files for each key functionality.
Project Overview

This IDS performs the following tasks:

    Traffic Capture: Uses libpcap to capture packets from a network interface.
    Detection Rules: Analyzes packets for signs of malicious activity.
        SYN Scan Detection: Detects SYN scans often used for reconnaissance.
        SQL Injection (SQLi) Detection: Identifies SQLi patterns in HTTP requests.
        Cross-Site Scripting (XSS) Detection: Detects XSS payloads in HTTP requests.
    Logging and Blocking: Logs detected events and blocks offending IPs using iptables.

Files and Directory Structure

IDS/
├── main.c                 # Entry point for the IDS, initializes packet capture.
├── block.c                # Contains the function to block IPs.
├── block.h                # Header file for block.c.
├── log.c                  # Contains the function for logging alerts.
├── log.h                  # Header file for log.c.
├── sqli.c                 # Contains SQLi detection logic.
├── sqli.h                 # Header file for sqli.c.
├── xss.c                  # Contains XSS detection logic.
├── xss.h                  # Header file for xss.c.
├── packet_handler.c       # Processes packets and applies detection rules.
├── packet_handler.h       # Header file for packet_handler.c.
└── ids_alerts.log         # Log file for detected threats (generated at runtime).

Detailed Module Breakdown
1. main.c - Program Entry Point

The main file sets up the network device for capturing and starts the packet capture loop. It utilizes libpcap to list devices, select the first available network interface, and capture packets.

    Key Functions:
        main: Initializes the IDS, selects a device, opens it for live capture, and runs pcap_loop to process each packet with the packet_handler.

2. packet_handler.c - Packet Processing

This file contains the packet_handler function, which is triggered for every captured packet. It inspects packet headers and applies various rules to detect attacks.

    Detection Rules:
        SYN Scan Detection: Checks for TCP SYN packets without an ACK flag, a sign of port scanning.
        HTTP Traffic Analysis: Processes packets with port 80 (HTTP) for SQLi and XSS patterns.
        HTTPS Traffic Logging: Logs information about HTTPS traffic for monitoring (without inspection).
    Key Functions:
        packet_handler: Determines packet type and applies rules for SYN scan, SQLi, and XSS. It uses functions from sqli.h, xss.h, log.h, and block.h.

3. block.c - IP Blocking

This module provides the block_ip function, which uses iptables to block IP addresses associated with suspicious activities.

    Key Functions:
        block_ip: Executes an iptables command to drop all incoming traffic from a specific IP. This function runs iptables via execvp in a forked process to avoid shell access vulnerabilities.

    Error Handling: Checks if iptables command fails and logs an error message if blocking fails.

4. log.c - Alert Logging

This module handles logging detected events to ids_alerts.log, which stores each detection for later review.

    Key Functions:
        log_alert: Opens ids_alerts.log in append mode and writes the alert message. If the file fails to open, it logs an error.

5. sqli.c - SQL Injection Detection

This module contains the detect_sqli function, which uses regular expressions to identify SQLi patterns in HTTP packet payloads.

    Detection Pattern:
        Identifies common SQL injection signatures, such as ' OR 1=1, SELECT ... FROM, and UNION SELECT, using a regular expression.
    Key Functions:
        detect_sqli: Compiles a regex to match SQLi patterns and returns 1 if a match is found or 0 if not. Frees the compiled regex memory after usage.

6. xss.c - Cross-Site Scripting (XSS) Detection

This module provides the detect_xss function, which scans HTTP payloads for potential XSS attacks.

    Detection Pattern:
        Detects XSS patterns like <script>, javascript:, and event handlers like onerror= in payloads.

    Key Functions:
        detect_xss: Uses a regex to identify XSS patterns and returns 1 if a match is found or 0 if not.

Installation and Setup
Prerequisites

    libpcap: Install the libpcap library and its development headers.
        Ubuntu/Debian:

sudo apt update
sudo apt install libpcap-dev

CentOS/RHEL:

        sudo yum install libpcap-devel

Compiling the Project

To compile the project, navigate to the project directory and run:

gcc -o IDS main.c block.c log.c sqli.c xss.c packet_handler.c -lpcap

Running the IDS

Run the compiled binary with sudo to allow network capture and iptables modifications:

sudo ./IDS

    Note: The program requires root privileges for network monitoring and IP blocking.

Usage

Upon execution, the IDS will:

    Automatically select the first available network interface.
    Capture packets in real-time and analyze each packet for suspicious patterns.
    Log alerts to ids_alerts.log and block malicious IP addresses as defined by the detection rules.

Sample Output:

------------------------------AI BASED Intrusion Detection System---------------------------------
Using device: eth0
SYN scan detected: 192.168.1.10 -> 192.168.1.1
Blocked IP: 192.168.1.10
SQL Injection detected from: 203.0.113.5
Blocked IP: 203.0.113.5

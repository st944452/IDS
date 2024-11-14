Intrusion Detection System (IDS)

A simple Intrusion Detection System (IDS) written in C, leveraging libpcap for real-time network traffic monitoring and iptables to block malicious IP addresses. This program analyzes network packets and detects potential security threats based on predefined rules, including SYN scans, HTTP requests with SQL injection (SQLi), and Cross-Site Scripting (XSS) attack patterns.
Features

    Real-time Network Traffic Monitoring: Uses libpcap to capture live network packets from a specified interface.
    Pattern-Based Intrusion Detection:
        SYN Scan Detection: Identifies SYN scans, which are often used in reconnaissance activities to map open ports.
        SQL Injection (SQLi) Detection: Detects SQL injection patterns in HTTP traffic payloads.
        Cross-Site Scripting (XSS) Detection: Identifies XSS attack patterns embedded in HTTP traffic payloads.
    IP Blocking via iptables: Automatically blocks IP addresses associated with malicious activity using iptables.

How It Works

    Network Capture: The IDS uses libpcap to listen to network traffic on the specified interface in promiscuous mode.
    Packet Analysis: Each captured packet is analyzed based on:
        TCP SYN Scans: Detects SYN packets without ACK responses, indicating potential port scanning.
        HTTP Traffic: Examines HTTP payloads to identify SQLi and XSS attack patterns.
        HTTPS Traffic: Logs HTTPS traffic for monitoring purposes.
    Alert Logging: Detected attacks are logged to a file (ids_alerts.log) for analysis and record-keeping.
    IP Blocking: Malicious IPs are blocked using iptables to prevent further access to the network.

Setup and Installation
Prerequisites

    libpcap: The IDS relies on libpcap for packet capture.
        Install libpcap and its development headers:

        # Ubuntu/Debian
        sudo apt update
        sudo apt install libpcap-dev

        # CentOS/RHEL
        sudo yum install libpcap-devel

Compile the Program

    Clone or download the project files.
    Compile the program using gcc:

    gcc -o IDS IDS.c -lpcap

Run the Program

sudo ./IDS

    Note: The program requires root privileges to access the network interface in promiscuous mode and to execute iptables commands.

Usage Example

Upon execution, the IDS will:

    Detect network interfaces and choose the first available one for monitoring.
    Start capturing packets and analyzing them based on the intrusion rules.
    Log alerts for detected intrusions in ids_alerts.log.
    Block malicious IPs using iptables.

Sample Output:

------------------------------AI BASED Intrusion Detection System---------------------------------
Using device: eth0
SYN scan detected: 192.168.1.10 -> 192.168.1.1
Blocked IP: 192.168.1.10
SQL Injection detected from: 203.0.113.5
Blocked IP: 203.0.113.5

Project Structure

    IDS.c: The main source file containing all functionality for traffic monitoring, packet analysis, and IP blocking.
    ids_alerts.log: A log file where detected intrusion alerts are recorded.

Key Functions

    block_ip(const char *ip_address):
        Blocks the specified IP address using iptables.

    log_alert(const char *alert_msg):
        Logs detected intrusion alerts to ids_alerts.log.

    detect_sqli(const char *payload):
        Detects potential SQL injection patterns within HTTP payloads.

    detect_xss(const char *payload):
        Detects Cross-Site Scripting (XSS) attack patterns within HTTP payloads.

    packet_handler(...):
        Main packet analysis function that applies various rules for SYN scan, SQLi, and XSS detection.

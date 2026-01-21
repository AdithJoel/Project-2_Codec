# Project-2_Codec
Project-2_Honeypot
Building a Honeypot for Threat Detection and Analysis
A comprehensive Python-based honeypot system designed to attract and analyze malicious network traffic, providing hands-on experience with threat intelligence, attack pattern recognition, and cybersecurity monitoring.
🍯 Features

SSH Honeypot - Captures authentication attempts, credentials, and command execution
HTTP Honeypot - Logs web scanning, path enumeration, and vulnerability probing
Real-time Logging - All events captured in structured JSON format
Threat Analytics - Comprehensive analysis of attack patterns and IOCs
Multi-threaded - Handles concurrent connections efficiently
IOC Export - Generate threat intelligence reports for integration

📋 Prerequisites

Python 3.7+
Basic networking knowledge
Isolated environment (VM, Docker, or separate VLAN) - REQUIRED

🚀 Installation
bash# Clone the repository
git clone https://github.com/yourusername/honeypot-project.git
cd honeypot-project

# No additional dependencies required (pure Python standard library)
💻 Usage
Running the Honeypot
bashpython honeypot.py
Select honeypot type:
1. SSH Honeypot (Port 2222)
2. HTTP Honeypot (Port 8080)
3. Both
Testing Your Honeypot
bash# Test SSH Honeypot
telnet localhost 2222
ssh -p 2222 admin@localhost

# Test HTTP Honeypot
curl http://localhost:8080/admin
curl http://localhost:8080/wp-admin
curl http://localhost:8080/.env
Analyzing Captured Data
bash# Run the analyzer
python analyzer.py

# Or specify log file directly
python analyzer.py honeypot_logs.json
Using Individual Components
pythonfrom honeypot import SSHHoneypot, HTTPHoneypot

# SSH Honeypot
ssh_honeypot = SSHHoneypot(host='0.0.0.0', port=2222)
ssh_honeypot.start()

# HTTP Honeypot
http_honeypot = HTTPHoneypot(host='0.0.0.0', port=8080)
http_honeypot.start()

# Custom Analysis
from analyzer import HoneypotAnalyzer

analyzer = HoneypotAnalyzer('honeypot_logs.json')
top_attackers = analyzer.get_top_attackers(10)
credentials = analyzer.get_common_credentials(20)
analyzer.generate_report()
analyzer.export_iocs('threat_intel.txt')
🧪 What's Demonstrated
1. SSH Honeypot

Type: Low-interaction honeypot
Port: 2222 (configurable)
Captures:

IP addresses and connection attempts
Username/password combinations
Client SSH banners
Connection timestamps


Use Cases:

Detecting brute-force attacks
Credential stuffing detection
Bot activity monitoring



2. HTTP Honeypot

Type: Web application honeypot
Port: 8080 (configurable)
Captures:

Requested URLs and paths
User-Agent strings
HTTP headers
Vulnerability scanning patterns


Use Cases:

Web scanner detection
Exploit attempt logging
Attack vector identification



3. Threat Analysis Engine

Capabilities:

Top attacker identification
Credential analysis
Attack timeline visualization
Scanning pattern detection
IOC generation


Output Formats:

Console reports
JSON logs
CSV exports
IOC lists (IPs, credentials, patterns)



4. Real-World Attack Detection

Identifies common attack patterns
Tracks automated scanning tools
Captures malicious payloads
Generates actionable threat intelligence

📊 Example Output
Honeypot Logs
[*] SSH Honeypot listening on 0.0.0.0:2222
[*] HTTP Honeypot listening on 0.0.0.0:8080
[*] Logs will be saved to honeypot_logs.json
[*] Press Ctrl+C to stop

[2024-01-21T14:32:15] New attempt from 192.168.1.100:45322
  Username: admin
  Password: password123

[2024-01-21T14:33:42] GET /wp-admin from 45.76.132.98
  User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine)
Analysis Report
======================================================================
                    HONEYPOT ANALYSIS REPORT
======================================================================

Total Events: 247
Log File: honeypot_logs.json

======================================================================
TOP 10 ATTACKING IPs
======================================================================
192.168.1.100        -   45 attempts
45.76.132.98         -   32 attempts
103.224.182.251      -   28 attempts

======================================================================
CREDENTIAL ATTEMPTS (89 total)
======================================================================

Most Common Credentials:
  admin:password123                        -  23 times
  root:123456                              -  18 times
  admin:admin                              -  15 times

======================================================================
MOST REQUESTED PATHS
======================================================================
/admin                                             -  34 requests
/wp-admin                                          -  28 requests
/.env                                              -  21 requests
/phpmyadmin                                        -  19 requests

======================================================================
POTENTIAL SCANNERS (>5 requests)
======================================================================
45.76.132.98         -   32 requests
  First: 2024-01-21T10:15:32
  Last:  2024-01-21T10:47:18

======================================================================
ATTACK TIMELINE (by hour)
======================================================================
2024-01-21 10:00 | ████████████ 12
2024-01-21 11:00 | ████████████████████ 20
2024-01-21 12:00 | ████████ 8
🔑 Key Concepts Learned

Threat Intelligence - Understanding attacker tactics, techniques, and procedures (TTPs)
Attack Detection - Identifying malicious behavior patterns
Log Analysis - Extracting meaningful insights from security logs
Network Security - Understanding how attackers probe and exploit systems
Incident Response - Recognizing attack signatures and IOCs
Security Monitoring - Real-time threat detection capabilities
Honeypot Design - Low vs high interaction honeypots
Data Collection - Capturing and storing security events efficiently

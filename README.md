# Port Scan Detector

A Python tool that reads a network packet capture, detects port scans, and logs each alert to a SQLite database.

## Why I built this
In IST 220 and the Google Cybersecurity Certificate, I learned that port scans are often an attacker’s first move: mapping which services a machine is running before going after one. I wanted to see what a scan actually looks like at the packet level and build a tool that catches it.
## How it works
1. Reads every packet from a .pcap or .pcapng file using Scapy
2. Keeps only TCP connection attempts (SYN flag on, ACK off)
3. Slides a time window (default 10 seconds) over each source IP's attempts and counts the different ports inside it
4. Flags any IP that hits the threshold (default 20 ports) and saves the alert to SQLite with parameterized queries

## Setup
Install the dependencies: `pip install -r requirements.txt`

## Usage
- Scan a capture: `python detector.py samples/sample_scan.pcap`
- Adjust sensitivity: `python detector.py capture.pcapng --threshold 50 --window 5`
- View saved alerts: `python detector.py --history`

## Example output
Running the detector on a real Nmap scan of my own machine (`nmap -sT -p 1-1000 127.0.0.1`), captured in Wireshark:

```
Read 999 connection attempts from captures/my_scan.pcapng
[ALERT] Possible port scan from 127.0.0.1: 999 ports between 2026-11-02T20:00:51+00:00 and 2026-11-02T20:00:51+00:00
Saved 1 alert(s) to alerts.db
```

## Testing
- `generate_sample.py` builds a test capture with normal traffic plus one known scan (192.168.1.66, 200 ports in about 4 seconds). The detector flags only that IP.
- Tested against a real Nmap connect scan of my own machine, captured in Wireshark on the loopback interface. It caught 999 of 1,000 ports scanned in 0.27 seconds.

## Limitations
- Slow scans that stay under the threshold aren't caught. A wider window catches them but raises more false positives.
- Reads saved captures only; it doesn't monitor live traffic yet.

## What I learned
I learned what a port scan actually looks like in network traffic by watching one in Wireshark: a burst of SYN packets, red RST replies from closed ports, and Nmap jumping between ports in random order. I also learned that what separates a scan from normal traffic is speed and spread (one source hitting many different ports within seconds), and that ;`?` placeholders in SQL queries prevent SQL injection by keeping data separate from the command.

## Responsible use
I only tested this on my own laptop. Only scan networks and devices you own or have permission to test.
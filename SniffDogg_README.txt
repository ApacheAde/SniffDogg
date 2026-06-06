================================================================================
  SniffDogg
  Educational network packet sniffer
================================================================================

LEGAL NOTICE
------------
Use SniffDogg only on networks you own or have explicit written permission to
monitor. Capturing traffic on networks without authorization may violate local
laws and organizational policies.

SniffDogg is intended for:
  - Classroom labs and self-study
  - Authorized penetration testing
  - Debugging applications on your own machines
  - CTF and isolated test environments

Do not use SniffDogg to intercept passwords, personal data, or communications
on networks you do not control.


OVERVIEW
--------
SniffDogg is a Python packet sniffer that captures live network traffic,
parses common protocol headers, and writes human-readable records to a plain
text .txt file.

Captured and parsed layers:
  - Ethernet (MAC addresses, frame type)
  - IPv4 (source/destination IP, TTL, protocol)
  - TCP (ports, flags, sequence/acknowledgement numbers)
  - UDP (ports, length)
  - ICMP (type and code)

Non-IPv4 frames (ARP, IPv6, etc.) are logged with Ethernet details only.


REQUIREMENTS
------------
  - Python 3.8 or newer
  - Linux (uses AF_PACKET raw sockets)
  - Root privileges for live capture
      sudo python3 SniffDogg.py ...


FILES
-----
  SniffDogg.py          Main program
  SniffDogg_README.txt  This file


QUICK START
-----------
1. List available interfaces:

   python3 SniffDogg.py --list-interfaces

2. Capture 10 packets on the default interface:

   sudo python3 SniffDogg.py --count 10 --verbose

3. Open the generated log file:

   cat capture_YYYYMMDD_HHMMSS.txt


USAGE EXAMPLES
--------------

Capture on a specific interface:

  sudo python3 SniffDogg.py --interface eth0 --verbose

Save to a custom output file:

  sudo python3 SniffDogg.py -i wlan0 -o my_capture.txt -c 25

Capture only TCP traffic:

  sudo python3 SniffDogg.py -i eth0 -p tcp -c 50 -o tcp_capture.txt

Capture for 30 seconds:

  sudo python3 SniffDogg.py -i eth0 -t 30 -o short_capture.txt

Continuous capture until Ctrl+C:

  sudo python3 SniffDogg.py -i eth0 -o full_session.txt -v


COMMAND-LINE OPTIONS
--------------------
  -i, --interface IFACE   Network interface to capture on
  -o, --output FILE       Output .txt log file
  -c, --count N           Stop after N packets examined
  -t, --timeout SECONDS   Stop after a time limit
  -p, --protocol PROTO    Filter by protocol: tcp, udp, icmp
  -v, --verbose           Print one-line summaries to the terminal
  --list-interfaces       List interfaces and exit
  -h, --help              Show help message


OUTPUT FILE FORMAT
------------------
Each packet is written as a readable text block:

  [2026-06-06 14:30:01.123456] Packet #1
    Interface : eth0
    Length    : 74 bytes
    Summary   : 192.168.1.10:443 -> 192.168.1.50:52431 TCP [SYN]
    Ethernet: aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66 type=IPv4
    IPv4: 192.168.1.10 -> 192.168.1.50 proto=TCP ttl=64 len=60
    TCP: 443 -> 52431 flags=[SYN] seq=123456 ack=0
    Payload   : (empty)
  ------------------------------------------------------------------------

The file begins with a short session header noting the interface, start time,
packet limit, and protocol filter.


TIPS
----
  - Generate test traffic in a lab with ping, curl, or netcat to see packets
  - Use --count during early experiments to avoid huge log files
  - Use --protocol to focus on one traffic type
  - Run --list-interfaces if capture fails due to a wrong interface name
  - Press Ctrl+C to stop an unlimited capture session cleanly


TROUBLESHOOTING
---------------
  "Packet capture requires root privileges"
      Run the program with sudo.

  "could not open interface"
      Check the interface name with --list-interfaces.

  No packets captured
      Confirm the interface is active and try generating traffic (ping, curl).

  Empty or sparse logs with --protocol
      The filter only keeps matching IPv4 protocols; other traffic is skipped.


LIMITATIONS
-----------
  - Linux only in this version
  - IPv6 parsing is not included (frames are logged at Ethernet level only)
  - Payload is shown as hex preview, not decoded application data
  - Not designed for high-throughput production monitoring
  - For advanced analysis, consider Wireshark or tcpdump


RELATED TOOLS
-------------
  - tcpdump     Command-line capture utility
  - Wireshark   GUI protocol analyzer
  - tshark      Wireshark command-line companion

================================================================================
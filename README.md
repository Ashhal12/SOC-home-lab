# SOC Home Lab — Personal Threat Detection System

A fully functional Security Operations Center (SOC) Home Lab built from scratch using open-source tools. This project simulates a real-world attack-detection environment with three virtual machines — an attacker, a victim, and a centralized SIEM monitoring server.

---

## Lab Architecture

| Machine | IP Address | Role | Tools |
|---|---|---|---|
| Ubuntu 25.04 | 192.168.74.139 | SIEM / Monitor | Suricata, Wazuh, Filebeat, Flask |
| Kali Linux 2025.2 | 192.168.74.129 | Attacker | Nmap, Metasploit |
| Windows 10 x64 | 192.168.74.140 | Victim | Wazuh Agent, Wireshark |

All machines are hosted on VMware Workstation Pro 17 and communicate over a NAT network (192.168.74.0/24).

---

## Tools & Technologies

- **VMware Workstation Pro 17** — Virtualization platform
- **Suricata 7.0.8** — Network Intrusion Detection System (NIDS)
- **Wazuh 4.14.5** — SIEM: Manager + Indexer (OpenSearch) + Dashboard
- **Wazuh Agent** — Endpoint monitoring on Windows 10
- **Filebeat 7.10.2** — Log shipping to Wazuh Indexer
- **Python Flask** — Custom real-time SOC dashboard
- **Nmap 7.95** — Network reconnaissance and port scanning
- **Metasploit 6.4.84** — Exploitation framework
- **Wireshark** — Packet capture and analysis
- **MITRE ATT&CK** — Threat intelligence framework (auto-mapped by Wazuh)

---

## Custom Suricata Detection Rules

Six custom rules were written to detect specific attack patterns:

```
alert tcp any any -> 192.168.74.139 any (msg:"PORT SCAN DETECTED - Nmap SYN Scan"; flags:S; threshold: type threshold, track by_src, count 20, seconds 3; sid:9000001; rev:1;)

alert icmp any any -> 192.168.74.139 any (msg:"PING SWEEP DETECTED - ICMP from Kali"; itype:8; sid:9000002; rev:1;)

alert tcp any any -> 192.168.74.139 22 (msg:"SSH BRUTE FORCE ATTEMPT DETECTED"; flags:S; threshold: type threshold, track by_src, count 5, seconds 10; sid:9000003; rev:1;)

alert tcp any any -> 192.168.74.139 80 (msg:"HTTP ATTACK DETECTED - Web Server Probe"; flags:S; threshold: type threshold, track by_src, count 10, seconds 5; sid:9000004; rev:1;)

alert tcp any any -> 192.168.74.139 any (msg:"AGGRESSIVE PORT SCAN DETECTED - Multiple Ports"; flags:S; threshold: type threshold, track by_src, count 50, seconds 5; sid:9000005; rev:1;)

alert udp any any -> 192.168.74.139 any (msg:"UDP SCAN DETECTED - Possible Reconnaissance"; threshold: type threshold, track by_src, count 10, seconds 3; sid:9000006; rev:1;)
```

---

## Flask Dashboard (app.py)

A custom Python Flask dashboard was built to display live alerts from both Suricata and Wazuh. It auto-refreshes every 10 seconds and is accessible at `http://192.168.74.139:5000`.

Features:
- Live Suricata IDS alert feed (last 50 alerts)
- Live Wazuh SIEM event feed (last 20 events)
- Host cards for all three lab machines
- Key metrics: total alerts, active VMs, IDS status

---

## Attack Simulation & Results

Attacks were launched from Kali Linux using Nmap:

```bash
nmap -sS 192.168.74.139    # SYN Scan on Ubuntu SIEM
nmap -A 192.168.74.139     # Aggressive Scan
nmap -sS 192.168.74.140    # SYN Scan on Windows Victim
nmap -A 192.168.74.140     # Aggressive Scan
```

### Detection Results

| Attack | Suricata | Wazuh | Wireshark |
|---|---|---|---|
| Nmap SYN Scan | PORT SCAN DETECTED | Logged | RST/ACK visible |
| Ping Sweep | PING SWEEP DETECTED | Logged | ICMP visible |
| Aggressive Scan | AGGRESSIVE PORT SCAN | Logged | Visible |
| OS Detection | ET rules fired | Logged | TLS handshake |
| Windows Endpoint | N/A | Wazuh Agent | N/A |

### MITRE ATT&CK Techniques Detected

- **T1046** — Network Service Discovery (Nmap scanning)
- **T1078** — Valid Accounts (sudo and PAM events)
- **T1070** — Indicator Removal (file deletion on Windows)
- **T1489** — Service Stop (service modification events)

---

## How to Start the Lab

Start all services on Ubuntu:

```bash
sudo systemctl start wazuh-indexer wazuh-manager wazuh-dashboard suricata filebeat
```

Start Flask dashboard:

```bash
cd ~/soc-dashboard && sudo python3 app.py
```

Access Wazuh Dashboard:

```
https://192.168.74.139
```

Access Flask Dashboard:

```
http://192.168.74.139:5000
```

Monitor Suricata alerts live:

```bash
sudo tail -f /var/log/suricata/fast.log
```

---

## Project By

**Ashhal Yasir** — Air University, BS-CYS-F-24-A  
Group members: Muhammad Saim Chaudhry, Eman Shabir

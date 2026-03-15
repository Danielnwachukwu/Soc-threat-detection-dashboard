# Snort IDS Auto-Blocking with pfSense

This project is a SOC automation script that monitors Snort IDS alerts and automatically blocks malicious IP addresses on a pfSense firewall.

## Features
- Monitors Snort alert logs
- Detects attack patterns
- Automatically blocks attacker IPs
- Temporary blocking system
- Safe IP whitelist

## Technologies Used
- Python
- Snort IDS
- pfSense Firewall
- Paramiko (SSH automation)

## Lab Environment
- Kali Linux attacker
- pfSense firewall
- Snort IDS
- Host-only network

## How It Works
1. Snort generates alerts.
2. The script monitors `/var/log/snort/.../alert`.
3. Attacker IP is extracted.
4. Script connects to pfSense via SSH.
5. IP is automatically blocked.

## Disclaimer
This project was built for educational SOC lab purposes.

import paramiko
import re
import time
from collections import defaultdict

# ---------------- CONFIG ----------------

HOST = ("HOST IP")
USER = ("USERNAME")
PASSWORD =("PASSWORD")

SNORT_ALERT_FILE = "/var/log/snort/snort_em162360/alert"

CHECK_INTERVAL = 3
TEMP_BLOCK_TIME = 5

KALI_IP = "192.X.X.X"

HOST_ONLY_NETWORK = "192.X.X.X"

SAFE_IPS = [
    "192.X.X.X",
    "192.X.X.X",
    "192.X.X.X",
    "0.0.0.0",
    "255.255.255.255"
]

blocked_ips = {}

attack_counter = defaultdict(int)
total_threats = 0


# ---------------- COLORS ----------------

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"


# ---------------- MITRE ATTACK DATABASE ----------------

MITRE_ATTACK = {

    "T1046": {
        "keywords": ["scan", "nmap", "ping"],
        "tactic": "Discovery",
        "technique": "Network Service Discovery",
        "score": 4
    },

    "T1110": {
        "keywords": ["brute", "login failure"],
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "score": 7
    },

    "T1078": {
        "keywords": ["valid login", "authentication"],
        "tactic": "Credential Access",
        "technique": "Valid Accounts",
        "score": 6
    },

    "T1021": {
        "keywords": ["remote service", "session traversal"],
        "tactic": "Lateral Movement",
        "technique": "Remote Services",
        "score": 6
    },

    "T1105": {
        "keywords": ["trojan", "malware"],
        "tactic": "Command and Control",
        "technique": "Ingress Tool Transfer",
        "score": 8
    },

    "T1041": {
        "keywords": ["exfiltration"],
        "tactic": "Exfiltration",
        "technique": "Exfiltration Over C2 Channel",
        "score": 9
    },

    "T1499": {
        "keywords": ["dos", "flood"],
        "tactic": "Impact",
        "technique": "Endpoint Denial of Service",
        "score": 8
    }

}


# ---------------- BANNER ----------------

def banner():

    print(BLUE)
    print("=======================================================")
    print(" SNARF-X - MITRE ATT&CK Driven SOC Automation Platform ")
    print("=======================================================")
    print(RESET)


# ---------------- EXTRACT IP ----------------

def extract_ip(log):

    ips = re.findall(r'\d+\.\d+\.\d+\.\d+', log)

    valid = []

    for ip in ips:

        if ip not in SAFE_IPS:

            valid.append(ip)

    return list(set(valid))


# ---------------- MITRE ANALYSIS ----------------

def mitre_analysis(log):

    score = 0

    for technique_id in MITRE_ATTACK:

        data = MITRE_ATTACK[technique_id]

        for keyword in data["keywords"]:

            if keyword.lower() in log.lower():

                print(RED + "\n[MITRE ATT&CK DETECTED]" + RESET)
                print(RED + f"Technique ID : {technique_id}" + RESET)
                print(RED + f"Tactic       : {data['tactic']}" + RESET)
                print(RED + f"Technique    : {data['technique']}" + RESET)

                score += data["score"]

    return score


# ---------------- SOC DASHBOARD ----------------

def show_dashboard():

    print("\n" + BLUE + "------ SOC DASHBOARD ------" + RESET)

    if attack_counter:

        top_ip = max(attack_counter, key=attack_counter.get)

        print(GREEN + f"Total Threat Events : {total_threats}" + RESET)
        print(GREEN + f"Top Attacker        : {top_ip}" + RESET)
        print(GREEN + f"Attack Frequency    : {attack_counter[top_ip]}" + RESET)

    else:

        print(GREEN + "No threats detected yet" + RESET)


# ---------------- BLOCK FUNCTIONS ----------------

def temporary_block(ssh, ip):

    print(YELLOW + f"[TEMP BLOCK 5s] → {ip}" + RESET)

    ssh.exec_command(f"pfctl -t snort2c -T add {ip}")

    blocked_ips[ip] = time.time()


def permanent_block(ssh, ip):

    print(RED + f"[PERMANENT BLOCK] → {ip}" + RESET)

    ssh.exec_command(f"pfctl -t snort2c -T add {ip}")


def unblock_expired(ssh):

    now = time.time()

    for ip in list(blocked_ips.keys()):

        if now - blocked_ips[ip] > TEMP_BLOCK_TIME:

            print(GREEN + f"[UNBLOCKED] → {ip}" + RESET)

            ssh.exec_command(f"pfctl -t snort2c -T delete {ip}")

            del blocked_ips[ip]


# ---------------- SSH CONNECTION ----------------

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

ssh.connect(HOST, username=USER, password=PASSWORD)

banner()

print(GREEN + "Connected to pfSense IDS monitoring..." + RESET)


# ---------------- REAL TIME MONITOR ----------------

while True:

    stdin, stdout, stderr = ssh.exec_command(
        f"tail -n 10 {SNORT_ALERT_FILE}"
    )

    logs = stdout.read().decode()

    if logs.strip() == "":
        time.sleep(CHECK_INTERVAL)
        continue

    print("\n" + BLUE + "------ SNORT ALERT STREAM ------" + RESET)

    behavior_score = mitre_analysis(logs)

    ips = extract_ip(logs)

    if ips:

        print(GREEN + f"Detected IPs: {ips}" + RESET)

    for ip in ips:

        total_threats += 1

        attack_counter[ip] += 1

        threat_score = attack_counter[ip] + behavior_score

        print(GREEN + f"Threat Score for {ip}: {threat_score}" + RESET)

        # Demo attacker (temporary block)

        if ip == KALI_IP:

            if ip not in blocked_ips:

                temporary_block(ssh, ip)

            continue

        # External attackers permanent block

        if not ip.startswith(HOST_ONLY_NETWORK):

            permanent_block(ssh, ip)

            continue

    show_dashboard()

    unblock_expired(ssh)

    time.sleep(CHECK_INTERVAL)

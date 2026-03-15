
# Write a Python SOC automation script that monitors Wazuh alerts from:
# /var/ossec/logs/alerts/alerts.json
#
# The script should read alerts continuously and classify attacks based on rule IDs.
#
# Attacks already tested in my SOC lab include:
#
# - SSH brute force attacks (rule 5716, 5503)
# - Successful SSH login / lateral movement (5715)
# - Privilege escalation using sudo (5402, 100500)
# - PAM login session events (5501)
# - AppArmor denied actions (52002)
# - SQL injection web attacks
# - HTTP / HTTPS attacks on Apache
# - Nikto web scanning
# - SMTP attacks
# - SNMP enumeration
# - Telnet attacks
# - Port scanning (Nmap)
#
# Categorize alerts using MITRE ATT&CK stages:
#
# Reconnaissance
# Credential Access
# Lateral Movement
# Privilege Escalation
# Persistence
# Defense Evasion
#
# The script should:
# - Continuously monitor alerts.json
# - Parse each alert
# - Identify attack type
# - Print formatted output like:
#
# [ATTACK TYPE] Agent: <agent name> Rule: <rule id> Description: <description>
#
# The script should run continuously like a SOC monitoring tool.
import json
import time 

def classify_attack(rule_id):
    if rule_id in [5716, 5503]:
        return "SSH Brute Force Attack"
    elif rule_id == 5715:
        return "Successful SSH Login / Lateral Movement"
    else:
        return "Unknown Attack Type"
    
def monitor_alerts(file_path):
    with open(file_path, 'r') as f:
       # f.seek(0, 2)  # Move the cursor to the end of the file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)  # Sleep briefly to avoid busy waiting
                continue
            
            try:
                alert = json.loads(line)
                rule_id = int(alert.get('rule', {}).get('id'))
                agent_name = alert.get('agent', {}).get('name')
                description = alert.get('rule', {}).get('description')
                
                attack_type = classify_attack(rule_id)
                print(f"[{attack_type}] Agent: {agent_name} Rule: {rule_id} Description: {description}")
            except json.JSONDecodeError:
                continue  # Skip lines that are not valid JSON
if __name__ == "__main__":
    monitor_alerts('/var/ossec/logs/alerts/alerts.json')











    
    

    

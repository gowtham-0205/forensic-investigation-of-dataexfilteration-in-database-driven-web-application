import os
import pandas as pd
from datetime import datetime

# Step 1: Define project scope and objectives
print("Initializing Forensic Investigation Project...")

# Define severity levels
SEVERITY_LEVELS = {
    "SQL Injection": "High",
    "Insider Threat": "Critical",
    "Malware-Based Exfiltration": "High",
    "Covert Channel Exfiltration": "Medium"
}

# Create a function to log incidents
def log_incident(attack_type, description, impact, mitigation):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    severity = SEVERITY_LEVELS.get(attack_type, "Low")
    
    incident_data = {
        "Timestamp": timestamp,
        "Attack Type": attack_type,
        "Description": description,
        "Severity": severity,
        "Impact": impact,
        "Mitigation": mitigation
    }
    
    # Save log to CSV
    log_file = "forensic_report.csv"
    if not os.path.exists(log_file):
        df = pd.DataFrame(columns=incident_data.keys())
        df.to_csv(log_file, index=False)
    
    df = pd.read_csv(log_file)
    df = df.append(incident_data, ignore_index=True)
    df.to_csv(log_file, index=False)
    
    print(f"[LOGGED] {attack_type} incident recorded.")

# Example attack logs
log_incident("SQL Injection", "Extracted user credentials via vulnerable query", "User data exposed", "Use prepared statements and input validation")
log_incident("Insider Threat", "Unauthorized access to sensitive files", "Confidential data leaked", "Implement strict access controls and monitoring")
log_incident("Malware-Based Exfiltration", "Keylogger captured keystrokes and sent data externally", "Sensitive credentials compromised", "Deploy endpoint security and anomaly detection")

print("Forensic investigation report generated: forensic_report.csv")

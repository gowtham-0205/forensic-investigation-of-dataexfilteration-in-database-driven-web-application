from datetime import datetime
import os
import json
import hashlib
import random

def perform_timeline_analysis():
    """
    Analyze logs to create a timeline of suspicious events
    """
    attack_sequences = []
    
    # If forensic_report.csv exists, use it to generate a timeline
    if os.path.exists("forensic_report.csv"):
        try:
            import pandas as pd
            df = pd.read_csv("forensic_report.csv")
            
            # Filter to only attacks or suspicious activities
            attack_df = df[df["Attack Detected"] != "None"]
            
            for _, row in attack_df.iterrows():
                attack_sequences.append({
                    "timestamp": row["Timestamp"],
                    "event": f"{row['Attack Detected']} from IP {row['IP Address']} by user '{row['Username']}'"
                })
                
            # If we have no attacks, add a placeholder
            if len(attack_sequences) == 0:
                attack_sequences.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "event": "No attacks detected in logs"
                })
                
        except Exception as e:
            print(f"Error in timeline analysis: {e}")
            attack_sequences.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event": f"Error analyzing timeline: {str(e)}"
            })
    else:
        attack_sequences.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event": "No forensic logs available for analysis"
        })
    
    return attack_sequences

def implement_honeytokens():
    """
    Create honeytokens for detecting unauthorized data access
    """
    honeytokens = {
        "admin_api_key": "htoken_" + hashlib.md5(f"admin_{random.randint(1000, 9999)}".encode()).hexdigest(),
        "dummy_password": "htoken_" + hashlib.md5(f"password_{random.randint(1000, 9999)}".encode()).hexdigest(),
        "fake_credit_card": "htoken_" + hashlib.md5(f"4111_{random.randint(1000, 9999)}_1111".encode()).hexdigest(),
        "fake_token": "htoken_" + hashlib.md5(f"token_{random.randint(1000, 9999)}".encode()).hexdigest(),
        "honeypot_db_credential": "htoken_" + hashlib.md5(f"dbuser_{random.randint(1000, 9999)}".encode()).hexdigest()
    }
    
    return honeytokens

def generate_file_hashes(directory):
    """
    Generate hashes for files in a directory to detect tampering
    """
    file_hashes = {}
    important_extensions = ['.py', '.html', '.js', '.db', '.csv', '.json']
    
    try:
        for root, _, files in os.walk(directory):
            for file in files:
                # Skip files in the venv directory and large files
                if 'venv' in root or '.git' in root:
                    continue
                
                file_path = os.path.join(root, file)
                
                # Only hash important files
                _, ext = os.path.splitext(file)
                if ext.lower() not in important_extensions:
                    continue
                
                try:
                    if os.path.getsize(file_path) < 10 * 1024 * 1024:  # 10MB limit
                        with open(file_path, 'rb') as f:
                            file_hash = hashlib.sha256(f.read()).hexdigest()
                            file_hashes[file_path] = file_hash
                except Exception as e:
                    print(f"Error hashing {file_path}: {e}")
    except Exception as e:
        print(f"Error walking directory: {e}")
    
    # Limit to 10 files to prevent overwhelming the display
    if len(file_hashes) > 10:
        important_files = {k: file_hashes[k] for k in list(file_hashes.keys())[:10]}
        return important_files
    
    return file_hashes

def generate_forensic_report(case_id, timestamp, analyst):
    """
    Generate a sample forensic report for demonstration
    """
    # Get real data if available
    attack_sequences = perform_timeline_analysis()
    
    # Get some sample findings based on the timeline or use defaults
    if len(attack_sequences) > 1 and attack_sequences[0]["event"] != "No attacks detected in logs":
        findings = [
            f"Multiple attack attempts detected from timeline analysis",
            f"Possible {attack_sequences[0]['event'].split(' ')[0]} attack vector identified",
            "User credentials may have been compromised"
        ]
        attack_vectors = [seq["event"].split(" from")[0] for seq in attack_sequences[:3]]
        severity = "High" if any("SQL Injection" in seq["event"] or "Data Exfiltration" in seq["event"] for seq in attack_sequences) else "Medium"
    else:
        findings = [
            "No active threats detected in system logs",
            "Baseline security monitoring is active",
            "System integrity checks are passing"
        ]
        attack_vectors = ["None identified"]
        severity = "Low"
    
    # Generate standard recommendations
    recommendations = [
        "Implement IP rate limiting to prevent brute force attempts",
        "Increase log verbosity for login attempts",
        "Consider implementing CAPTCHA for repeated failed login attempts",
        "Review user access permissions on regular basis",
        "Implement multi-factor authentication for admin accounts"
    ]
    
    return {
        "case_id": case_id,
        "timestamp": timestamp,
        "analyst": analyst,
        "severity": severity,
        "findings": findings,
        "attack_vectors": attack_vectors,
        "recommendations": recommendations
    }
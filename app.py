from flask import Flask, request, render_template, g, make_response, send_from_directory
import sqlite3
import os
import re
import pandas as pd
from datetime import datetime
from network_analysis import analyze_network_traffic, check_data_volume
from database_monitor import monitor_database_activity, track_database_size_changes
from forensic_analysis import perform_timeline_analysis, implement_honeytokens, generate_file_hashes, generate_forensic_report
from flask_socketio import SocketIO
import json
import time

# Initialize Flask app first
app = Flask(__name__, template_folder=os.path.join(os.getcwd(), "templates"))
socketio = SocketIO(app)
DATABASE = "vulnerable.db"

# Create necessary directories
if not os.path.exists("reports"):
    os.makedirs("reports")

if not os.path.exists("security_incidents"):
    os.makedirs("security_incidents")

if not os.path.exists("static"):
    os.makedirs("static")
if not os.path.exists("static/components"):
    os.makedirs("static/components")
if not os.path.exists("static/js"):
    os.makedirs("static/js")

def sanitize_filename(filename):
    return re.sub(r'[^\w\-_]', '_', filename)

# Now that app is defined, you can use app.route
@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

# Rest of your functions and routes...

def handle_security_incident(event, username, query, ip_address, user_agent):
    case_id = str(datetime.now().timestamp())
    report = {
        "case_id": case_id,
        "event": event,
        "username": username,
        "query": query,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "timestamp": datetime.now().isoformat()
    }
    
    # Try writing the report with error handling
    try:
        with open(f'security_incidents/{case_id}.json', 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Report saved: security_incidents/{case_id}.json")
    except Exception as e:
        print(f"Error writing report: {e}")

    return case_id


@app.route("/data_flow", methods=["GET"])
def data_flow():
    # Get username from cookie
    username = request.cookies.get("user", "Guest")
    return render_template("data_flow.html", username=username)

# Initialize and get database connection
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

# Create a vulnerable users table and insert sample data
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")
        cursor.execute("INSERT INTO users (username, password) VALUES ('user1', 'password1')")
        db.commit()

# Update the log_forensic_incident function to emit real-time updates

# Update forensic_report route to include real-time logs
@app.route("/forensic_report", methods=["GET"])
def forensic_report():
    log_file = "forensic_report.csv"
    if not os.path.exists(log_file):
        return "No forensic logs available."

    df = pd.read_csv(log_file)
    severity_counts = df["Severity"].value_counts().to_dict()
    logs_html = df.to_html(classes="table table-striped", index=False)
    
    # Get username from cookie if available
    username = request.cookies.get("user", "Guest")
    
    return render_template("forensic_report.html", 
                          severity_counts=severity_counts, 
                          logs_html=logs_html,
                          username=username)



# Function to detect SQL Injection patterns
def detect_sql_injection(input_text):
    sql_patterns = [
        r"'.*?--",
        r"'.*? OR '1'='1",
        r"UNION SELECT",
        r"DROP TABLE",
        r"INSERT INTO",
        r"xp_cmdshell",
    ]
    for pattern in sql_patterns:
        if re.search(pattern, input_text, re.IGNORECASE):
            return True
    return False

# Function to detect XSS patterns
def detect_xss(input_string):
    """Detect XSS attempts in input"""
    xss_patterns = [
        "<script>", "</script>", "javascript:", "onerror=", "onload=",
        "eval(", "document.cookie", "<img", "alert(", "onclick=",
        "String.fromCharCode", "\\x", "<iframe", "<svg", "onmouseover="
    ]
    return any(pattern.lower() in input_string.lower() for pattern in xss_patterns)

# Add this function after the detect_xss function
def detect_data_exfiltration(input_string):
    """Detect data exfiltration attempts"""
    exfil_patterns = [
        "system(", "popen(", "exec(", "shell_exec(", "passthru(",
        "base64_encode(", "base64_decode(", "http://", "https://",
        "ftp://", ".php?data=", ".asp?data=", "webhook", "pastebin",
        "requestb.in", "ngrok"
    ]
    return any(pattern.lower() in input_string.lower() for pattern in exfil_patterns)


def log_forensic_incident(username, query, attack_detected, ip_address, user_agent, login_status):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file = "forensic_report.csv"
    
    # Standardize attack detected name
    if attack_detected and "exfiltration" in attack_detected.lower():
        attack_detected = "Data Exfiltration Attempt"  # Standardize name
    
    severity_mapping = {
        "SQL Injection Attempt Detected": "High",
        "XSS Attempt Detected": "Medium",
        "Failed Login Attempt": "Low",
        "Data Exfiltration Attempt": "High"
    }
        
    severity = severity_mapping.get(attack_detected, "None" if login_status == "Successful" else "Low")

    if not os.path.exists(log_file):
        df = pd.DataFrame(columns=["Timestamp", "Username", "Query", "Attack Detected", "Severity", "IP Address", "User Agent", "Login Status"])
        df.to_csv(log_file, index=False)

    df = pd.read_csv(log_file)
    new_entry = {
        "Timestamp": timestamp,
        "Username": username,
        "Query": query,
        "Attack Detected": attack_detected,
        "Severity": severity,
        "IP Address": ip_address,
        "User Agent": user_agent,
        "Login Status": login_status
    }
    df = df._append(new_entry, ignore_index=True)
    df.to_csv(log_file, index=False)

    # Emit the new log entry to the frontend
    socketio.emit("new_log", new_entry)
    
# Fix the API endpoint to better handle the exfiltration data
@app.route("/api/security/data-exfiltration", methods=["GET"])
def get_data_exfiltration_events():
    try:
        log_file = "forensic_report.csv"
        if not os.path.exists(log_file):
            print("Log file doesn't exist")
            return json.dumps([])
            
        df = pd.read_csv(log_file)
        print(f"Found {len(df)} total log entries")
        
        # More reliable search - look for both possible formats
        exfil_events = df[
            df["Attack Detected"].str.contains("Exfiltration", na=False, case=False) | 
            df["Attack Detected"].str.contains("Data Exfiltration Attempt", na=False, case=False)
        ]
        print(f"Found {len(exfil_events)} exfiltration events")
        
        events = []
        for _, row in exfil_events.iterrows():
            events.append({
                "timestamp": row["Timestamp"],
                "username": row["Username"],
                "method": "Web Form Input" if "password" in str(row["Query"]).lower() else "SQL Query",
                "ip_address": row["IP Address"],
                "severity": row["Severity"]
            })
        
        print(f"Returning {len(events)} events")
        return json.dumps(events)
    except Exception as e:
        print(f"Error fetching data exfiltration events: {e}")
        return json.dumps({"error": str(e)})

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        ip_address = request.remote_addr
        user_agent = request.headers.get("User-Agent")

        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        # First check if credentials match valid users before checking for attacks
        cursor = get_db().cursor()
        cursor.execute(query)
        user = cursor.fetchone()

        # If valid credentials, process login immediately
        if user and ((username == 'admin' and password == 'admin123') or 
                    (username == 'user1' and password == 'password1')):
            # Log successful login before returning response
            log_forensic_incident(username, query, "None", ip_address, user_agent, "Successful")
            
            response = make_response(render_template("welcome.html", username=username))
            response.set_cookie("user", username)
            return response
            
        # Now check for various security attacks
        attack_detected = None
        
        # Check for XSS - Corrected detection
        if detect_xss(username) or detect_xss(password):
            attack_detected = "XSS Attempt Detected"
            case_id = handle_security_incident(attack_detected, username, query, ip_address, user_agent)
            log_forensic_incident(username, query, attack_detected, ip_address, user_agent, "Failed")
            
            # Emit socket.io event for attack map
            socketio.emit('security_incident', {
                'incident_type': attack_detected,
                'severity': 'Medium',
                'source_ip': ip_address,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'details': f"XSS attack attempted in login form"
            })
            
            return f"🚨 Security incident detected. Case ID: {case_id}"
            
        # Check for Data Exfiltration - Corrected detection
        elif detect_data_exfiltration(username) or detect_data_exfiltration(password):
            attack_detected = "Data Exfiltration Attempt"
            case_id = handle_security_incident(attack_detected, username, query, ip_address, user_agent)
            log_forensic_incident(username, query, attack_detected, ip_address, user_agent, "Failed")
            
            # Emit socket.io event for attack map
            socketio.emit('security_incident', {
                'incident_type': attack_detected,
                'severity': 'High',
                'source_ip': ip_address,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'details': f"Data exfiltration attempt detected in login form"
            })
            
            return f"🚨 Security incident detected. Case ID: {case_id}"
        
        # Check for SQL Injection
        elif detect_sql_injection(username) or detect_sql_injection(password):
            attack_detected = "SQL Injection Attempt Detected"
            case_id = handle_security_incident(attack_detected, username, query, ip_address, user_agent)
            log_forensic_incident(username, query, attack_detected, ip_address, user_agent, "Failed")
            
            # Emit socket.io event for attack map
            socketio.emit('security_incident', {
                'incident_type': attack_detected,
                'severity': 'High',
                'source_ip': ip_address,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'details': f"SQL Injection attempted in login form by user '{username}'"
            })
            
            return f"🚨 Security incident detected. Case ID: {case_id}"
            
        # Check for Directory Traversal
        elif detect_directory_traversal(username) or detect_directory_traversal(password):
            attack_detected = "Directory Traversal Attempt"
            case_id = handle_security_incident(attack_detected, username, query, ip_address, user_agent)
            log_forensic_incident(username, query, attack_detected, ip_address, user_agent, "Failed")
            
            # Emit socket.io event for attack map
            socketio.emit('security_incident', {
                'incident_type': attack_detected,
                'severity': 'High',
                'source_ip': ip_address,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'details': f"Directory traversal attempt detected in login credentials"
            })
            
            return f"🚨 Security incident detected. Case ID: {case_id}"
            
        # Check for Command Injection
        elif detect_command_injection(username) or detect_command_injection(password):
            attack_detected = "Command Injection Attempt"
            case_id = handle_security_incident(attack_detected, username, query, ip_address, user_agent)
            log_forensic_incident(username, query, attack_detected, ip_address, user_agent, "Failed")
            
            # Emit socket.io event for attack map
            socketio.emit('security_incident', {
                'incident_type': attack_detected,
                'severity': 'Critical',
                'source_ip': ip_address,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'details': f"Command injection attempt detected in login credentials"
            })
            
            return f"🚨 Security incident detected. Case ID: {case_id}"
        
        # Check for SSRF - Corrected detection
        elif detect_ssrf(username) or detect_ssrf(password):
            attack_detected = "SSRF Attempt"
            case_id = handle_security_incident(attack_detected, username, query, ip_address, user_agent)
            log_forensic_incident(username, query, attack_detected, ip_address, user_agent, "Failed")
            
            # Emit socket.io event for attack map
            socketio.emit('security_incident', {
                'incident_type': attack_detected,
                'severity': 'High',
                'source_ip': ip_address,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'details': f"Server-side request forgery detected"
            })
            
            return f"🚨 Security incident detected. Case ID: {case_id}"
            
        # Check for Authentication Bypass - Corrected detection
        elif detect_auth_bypass(username) or detect_auth_bypass(password):
            attack_detected = "Authentication Bypass Attempt"
            case_id = handle_security_incident(attack_detected, username, query, ip_address, user_agent)
            log_forensic_incident(username, query, attack_detected, ip_address, user_agent, "Failed")
            
            # Emit socket.io event for attack map
            socketio.emit('security_incident', {
                'incident_type': attack_detected,
                'severity': 'High',
                'source_ip': ip_address,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'details': f"Authentication bypass attempt detected"
            })
            
            return f"🚨 Security incident detected. Case ID: {case_id}"
            
        # Check for API Token Exfiltration - Corrected detection
        elif detect_token_exfiltration(username) or detect_token_exfiltration(password):
            attack_detected = "API Token Exfiltration Attempt"
            case_id = handle_security_incident(attack_detected, username, query, ip_address, user_agent)
            log_forensic_incident(username, query, attack_detected, ip_address, user_agent, "Failed")
            
            # Emit socket.io event for attack map
            socketio.emit('security_incident', {
                'incident_type': attack_detected,
                'severity': 'High',
                'source_ip': ip_address,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'details': f"API token exfiltration attempt detected"
            })
            
            return f"🚨 Security incident detected. Case ID: {case_id}"
            
        # Check for Brute Force - Corrected detection
        elif detect_brute_force(request):
            attack_detected = "Brute Force Attack"
            case_id = handle_security_incident(attack_detected, username, query, ip_address, user_agent)
            log_forensic_incident(username, query, attack_detected, ip_address, user_agent, "Failed")
            
            # Emit socket.io event for attack map
            socketio.emit('security_incident', {
                'incident_type': attack_detected,
                'severity': 'Medium',
                'source_ip': ip_address,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'details': f"Brute force attack detected from IP {ip_address}"
            })
            
            return f"🚨 Security incident detected. Case ID: {case_id}"
            
        # Check for CSRF - Place this last to avoid catching other attacks
        elif detect_csrf(request):
            attack_detected = "CSRF Attempt"
            case_id = handle_security_incident(attack_detected, username, query, ip_address, user_agent)
            log_forensic_incident(username, query, attack_detected, ip_address, user_agent, "Failed")
            
            # Emit socket.io event for attack map
            socketio.emit('security_incident', {
                'incident_type': attack_detected,
                'severity': 'Medium',
                'source_ip': ip_address,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'details': f"CSRF attempt detected in form submission"
            })
            
            return f"🚨 Security incident detected. Case ID: {case_id}"
        
        # Check for network and database suspicious activity
        suspicious_network = analyze_network_traffic(request)
        if suspicious_network:
            case_id = handle_security_incident(f"Suspicious Network Activity: {', '.join(suspicious_network)}", 
                                           username, query, ip_address, user_agent)
            return f"🚨 Suspicious activity detected. Case ID: {case_id}"
        
        suspicious_db, db_reason = monitor_database_activity(query, username)
        if suspicious_db:
            case_id = handle_security_incident(f"Suspicious Database Activity: {db_reason}", 
                                           username, query, ip_address, user_agent)
            return f"🚨 Suspicious activity detected. Case ID: {case_id}"

        # If we got here, it means login failed but wasn't an attack
        log_forensic_incident(username, query, "Failed Login Attempt", ip_address, user_agent, "Failed")
        return "❌ Invalid credentials."

    return render_template("login.html")




@app.route("/vulnerability_report", methods=["GET"])
def vulnerability_report():
    log_file = "forensic_report.csv"
    if not os.path.exists(log_file):
        return "No forensic logs available."

    df = pd.read_csv(log_file)
    vulnerable_df = df[df["Severity"].isin(["High", "Medium", "Low"])]  # Only show vulnerabilities
    logs_html = vulnerable_df.to_html(classes="table table-danger", index=False)
    
    return render_template("vulnerability_report.html", logs_html=logs_html)

@app.route("/advanced_forensics", methods=["GET"])
def advanced_forensics():
    # Get username from cookie
    username = request.cookies.get("user", "Guest")
    
    # Generate file integrity hashes on first visit
    integrity_file = 'file_integrity.json'
    try:
        if not os.path.exists(integrity_file):
            file_hashes = generate_file_hashes(os.getcwd())
            # Write hashes to file to ensure they're available
            with open(integrity_file, 'w') as f:
                json.dump(file_hashes, f, indent=2)
        else:
            with open(integrity_file, 'r') as f:
                file_hashes = json.load(f)
        
        # Perform timeline analysis with error handling
        try:
            attack_sequences = perform_timeline_analysis()
        except Exception as e:
            print(f"Timeline analysis error: {e}")
            attack_sequences = [{"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                               "event": "Error generating timeline analysis"}]
        
        # Generate honeytokens with error handling
        try:
            honeytokens = implement_honeytokens()
        except Exception as e:
            print(f"Honeytoken generation error: {e}")
            honeytokens = {"error": "Failed to generate honeytokens"}
        
        # Create a sample forensic report with error handling
        try:
            sample_report = generate_forensic_report(
                f"CASE-{datetime.now().strftime('%Y%m%d-%H%M')}",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Forensic Investigator"
            )
        except Exception as e:
            print(f"Report generation error: {e}")
            sample_report = {"case_id": f"CASE-{datetime.now().strftime('%Y%m%d-%H%M')}",
                           "error": "Failed to generate complete report"}
        
        return render_template(
            "advanced_forensics.html",
            attack_sequences=attack_sequences,
            honeytokens=honeytokens,
            file_hashes=file_hashes,
            sample_report=sample_report,
            username=username  # Pass username to template
        )
    except Exception as e:
        # Fallback error handling
        return f"Error generating advanced forensics report: {str(e)}"
@app.route("/exfiltration_dashboard", methods=["GET"])
def exfiltration_dashboard():
    # Get username from cookie
    username = request.cookies.get("user", "Guest")
    return render_template("data_exfiltration.html", username=username)

# Add a new function to check for honeytokens in queries
def check_honeytoken_access(query):
    honeytokens = implement_honeytokens()
    for token_name, token_value in honeytokens.items():
        if token_value in query:
            return True, token_name
    return False, None

# Create an orchestrated incident response function
def handle_orchestrated_incident(incident_type, username, query, ip_address, user_agent):
    # Log the incident
    log_forensic_incident(username, query, incident_type, ip_address, user_agent, "Failed")
    
    # Generate a case ID
    case_id = f"CASE-{datetime.now().strftime('%Y%m%d-%H%M')}-{username}"
    
    # Create an incident report
    report = generate_forensic_report(case_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Automated System")
    
    # Add initial analysis
    honeytoken_accessed, token_name = check_honeytoken_access(query)
    if honeytoken_accessed:
        report["attack_vectors"].append(f"Honeytoken Access: {token_name}")
        report["severity"] = "Critical"
    
    # Perform timeline analysis
    attack_sequences = perform_timeline_analysis()
    if attack_sequences:
        report["attack_timeline"] = attack_sequences
    
    # Emit real-time alert
    socketio.emit("security_incident", {
        "case_id": case_id,
        "incident_type": incident_type,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity": "High" if "SQL Injection" in incident_type or "Data Exfiltration" in incident_type else "Medium"
    })
    
    # Save the report
    with open(f"reports/{case_id}.json", "w") as f:
        json.dump(report, f, indent=2)
    
    return case_id
@app.route("/test_attack", methods=["GET"])
def test_attack():
    """Endpoint to simulate different attack types for testing the attack map"""
    attack_type = request.args.get("type", "sql_injection")
    
    attack_types = {
        "sql_injection": {
            "incident_type": "SQL Injection Attempt",
            "severity": "High",
            "details": "Attempted to extract data with ' OR 1=1--"
        },
        "xss": {
            "incident_type": "XSS Attempt",
            "severity": "Medium",
            "details": "Attempted to inject <script>alert('XSS')</script>"
        },
        "data_exfiltration": {
            "incident_type": "Data Exfiltration Attempt",
            "severity": "High",
            "details": "Attempted to extract user data via UNION SELECT"
        },
        "directory_traversal": {
            "incident_type": "Directory Traversal Attempt",
            "severity": "High",
            "details": "Attempted to access ../../../etc/passwd"
        },
        "command_injection": {
            "incident_type": "Command Injection Attempt",
            "severity": "Critical",
            "details": "Attempted to execute ;cat /etc/passwd"
        },
        "csrf": {
            "incident_type": "CSRF Attempt",
            "severity": "Medium",
            "details": "Detected cross-site request without proper tokens"
        },
        "ssrf": {
            "incident_type": "SSRF Attempt",
            "severity": "High",
            "details": "Attempted to access internal service at http://localhost:8080"
        },
        "auth_bypass": {
            "incident_type": "Authentication Bypass Attempt",
            "severity": "High",
            "details": "Attempted to bypass auth with admin'--"
        },
        "token_exfiltration": {
            "incident_type": "API Token Exfiltration",
            "severity": "High",
            "details": "Attempted to extract API key from request"
        },
        "brute_force": {
            "incident_type": "Brute Force Attack",
            "severity": "Medium",
            "details": "Multiple failed login attempts detected"
        }
    }
    
    # Get attack info or default to SQL injection if type not found
    attack_info = attack_types.get(attack_type, attack_types["sql_injection"])
    
    # Generate random coordinates for visualization
    import random
    lat = random.uniform(-60, 70)
    lng = random.uniform(-180, 180)
    
    # Add source IP (user's IP or random one)
    source_ip = request.remote_addr
    if source_ip == "127.0.0.1":
        # Generate a fake external IP for better visualization
        source_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    
    # Emit a security incident for the attack map
    socketio.emit('security_incident', {
        'incident_type': attack_info["incident_type"],
        'severity': attack_info["severity"],
        'source_ip': source_ip,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'details': attack_info["details"],
        'lat': lat,
        'lng': lng,
        'case_id': f"TEST-{datetime.now().timestamp()}"
    })
    
    return {
        "status": "success",
        "message": f"Test {attack_info['incident_type']} event triggered",
        "coordinates": [lat, lng]
    }


        
def get_data_exfiltration_events():
    try:
        log_file = "forensic_report.csv"
        if not os.path.exists(log_file):
            print("Log file doesn't exist")
            return json.dumps([])
            
        df = pd.read_csv(log_file)
        print(f"Found {len(df)} total log entries")
        
        # Print all unique attack types to see what's being logged
        print("Unique attack types:", df["Attack Detected"].unique())
        
        # More flexible search
        exfil_events = df[df["Attack Detected"].str.contains("Exfiltration", na=False, case=False)]
        print(f"Found {len(exfil_events)} exfiltration events")
        
        events = []
        for _, row in exfil_events.iterrows():
            events.append({
                "timestamp": row["Timestamp"],
                "username": row["Username"],
                "method": "Web Form Input" if "password" in row["Query"].lower() else "SQL Query",
                "ip_address": row["IP Address"],
                "severity": row["Severity"]
            })
        
        print(f"Returning {len(events)} events")
        return json.dumps(events)
    except Exception as e:
        print(f"Error fetching data exfiltration events: {e}")
        return json.dumps({"error": str(e)})


# 1. Real-time Attack Map Visualization
@app.route("/attack_map", methods=["GET"])
def attack_map():
    username = request.cookies.get("user", "Guest")
    return render_template("attack_map.html", username=username)

@app.route("/api/attack_locations", methods=["GET"])
def attack_locations():
    try:
        # Read the forensic report
        log_file = "forensic_report.csv"
        if not os.path.exists(log_file):
            return json.dumps([])
            
        df = pd.read_csv(log_file)
        # Filter to only attacks
        attacks_df = df[df["Severity"].isin(["High", "Medium"])]
        
        # For demo purposes, generate fake geo locations for IPs
        # In a real app, you'd use a geolocation service
        import random
        locations = []
        
        for _, row in attacks_df.iterrows():
            ip = row["IP Address"]
            attack_type = row["Attack Detected"]
            severity = row["Severity"]
            
            # Generate random coordinates (for demo)
            lat = random.uniform(25, 65)
            lng = random.uniform(-120, 30)
            
            locations.append({
                "ip": ip,
                "attack_type": attack_type,
                "severity": severity,
                "lat": lat,
                "lng": lng,
                "timestamp": row["Timestamp"]
            })
            
        return json.dumps(locations)
    except Exception as e:
        print(f"Error generating attack locations: {e}")
        return json.dumps({"error": str(e)})

# 2. Security Recommendations Engine
@app.route("/security_recommendations", methods=["GET"])
def security_recommendations():
    username = request.cookies.get("user", "Guest")
    
    # Analyze the attack patterns
    log_file = "forensic_report.csv"
    recommendations = []
    
    if os.path.exists(log_file):
        df = pd.read_csv(log_file)
        
        # Count attack types
        attack_counts = df["Attack Detected"].value_counts()
        
        # Generate recommendations based on attack patterns
        if "SQL Injection Attempt Detected" in attack_counts and attack_counts["SQL Injection Attempt Detected"] > 0:
            recommendations.append({
                "title": "Implement Parameterized Queries",
                "description": "Replace string concatenation in SQL queries with parameterized queries to prevent SQL injection attacks.",
                "severity": "Critical",
                "implementation": "Use prepared statements or an ORM like SQLAlchemy."
            })
            
        if "XSS Attempt Detected" in attack_counts and attack_counts["XSS Attempt Detected"] > 0:
            recommendations.append({
                "title": "Enable Content Security Policy",
                "description": "Implement CSP headers to prevent cross-site scripting attacks.",
                "severity": "High",
                "implementation": "Add appropriate security headers to your Flask responses."
            })
            
        if "Data Exfiltration Attempt" in attack_counts and attack_counts["Data Exfiltration Attempt"] > 0:
            recommendations.append({
                "title": "Implement Data Loss Prevention",
                "description": "Set up data loss prevention systems to detect and block sensitive data exfiltration.",
                "severity": "Critical",
                "implementation": "Monitor outbound traffic for sensitive patterns and implement rate limiting."
            })
    
    # Add some default recommendations
    if not recommendations:
        recommendations = [
            {
                "title": "Regular Security Audits",
                "description": "Conduct regular security audits of your application code and infrastructure.",
                "severity": "Medium",
                "implementation": "Use automated tools like OWASP ZAP or manual code reviews."
            },
            {
                "title": "Enable Multi-Factor Authentication",
                "description": "Add an additional layer of security to user authentication.",
                "severity": "High",
                "implementation": "Integrate a TOTP service like Google Authenticator or SMS verification."
            }
        ]
        
    return render_template("security_recommendations.html", recommendations=recommendations, username=username)

# 3. Anomaly Detection System
def detect_anomalies():
    """Detect unusual patterns in login and security events"""
    try:
        log_file = "forensic_report.csv"
        if not os.path.exists(log_file):
            return []
            
        df = pd.read_csv(log_file)
        
        # Simple anomaly detection logic
        anomalies = []
        
        # 1. Multiple failed logins from same IP
        ip_counts = df[df["Login Status"] == "Failed"].groupby("IP Address").size()
        suspicious_ips = ip_counts[ip_counts > 3].index.tolist()
        
        for ip in suspicious_ips:
            anomalies.append({
                "type": "Multiple Failed Logins",
                "details": f"IP {ip} had {ip_counts[ip]} failed login attempts",
                "severity": "Medium"
            })
            
        # 2. Unusual login times (would need timestamp parsing)
        # This is placeholder logic - in a real app, you'd look at time patterns
        
        # 3. Quick succession of different attack types
        if len(df) >= 2:
            for i in range(1, len(df)):
                prev_row = df.iloc[i-1]
                curr_row = df.iloc[i]
                
                time_diff = pd.to_datetime(curr_row["Timestamp"]) - pd.to_datetime(prev_row["Timestamp"])
                if time_diff.total_seconds() < 10 and prev_row["Attack Detected"] != curr_row["Attack Detected"]:
                    anomalies.append({
                        "type": "Multiple Attack Techniques",
                        "details": f"Different attack types detected in quick succession from {curr_row['IP Address']}",
                        "severity": "High"
                    })
                    
        return anomalies
    except Exception as e:
        print(f"Error in anomaly detection: {e}")
        return []

@app.route("/anomaly_detection", methods=["GET"])
def anomaly_detection_dashboard():
    username = request.cookies.get("user", "Guest")
    anomalies = detect_anomalies()
    return render_template("anomaly_detection.html", anomalies=anomalies, username=username)

# 4. User authentication improvements
def implement_rate_limiting():
    """Implement a simple rate limiting system for login attempts"""
    # This would track login attempts by IP address
    # and block IPs that exceed a threshold
    pass

# 5. Add a comprehensive security dashboard
@app.route("/security_dashboard", methods=["GET"])
def security_dashboard():
    username = request.cookies.get("user", "Guest")
    
    # Get summary statistics
    log_file = "forensic_report.csv"
    stats = {
        "total_incidents": 0,
        "high_severity": 0,
        "medium_severity": 0,
        "low_severity": 0,
        "recent_attacks": []
    }
    
    if os.path.exists(log_file):
        df = pd.read_csv(log_file)
        stats["total_incidents"] = len(df)
        stats["high_severity"] = len(df[df["Severity"] == "High"])
        stats["medium_severity"] = len(df[df["Severity"] == "Medium"])
        stats["low_severity"] = len(df[df["Severity"] == "Low"])
        
        # Get 5 most recent attacks
        recent = df.sort_values("Timestamp", ascending=False).head(5)
        for _, row in recent.iterrows():
            stats["recent_attacks"].append({
                "timestamp": row["Timestamp"],
                "attack_type": row["Attack Detected"],
                "severity": row["Severity"],
                "username": row["Username"],
                "ip": row["IP Address"]
            })
    
    # Get anomalies
    anomalies = detect_anomalies()
    
    return render_template("security_dashboard.html", stats=stats, anomalies=anomalies, username=username)
# Add these functions to your app.py file

# 1. Directory Traversal Attack Detection
def detect_directory_traversal(input_string):
    """Detect directory traversal attempts"""
    traversal_patterns = [
        "../", "..\\", "%2e%2e%2f", "%252e%252e%252f",
        "/etc/passwd", "C:\\Windows\\", "/var/www", "boot.ini"
    ]
    return any(pattern.lower() in input_string.lower() for pattern in traversal_patterns)

def detect_command_injection(input_string):
    """Detect command injection attempts"""
    cmd_patterns = [
        "|", "||", "&", "&&", ";", "`", "$(",
        "cat ", "ping ", "wget ", "curl ", "nc ", "netcat "
    ]
    return any(pattern in input_string for pattern in cmd_patterns)

# 3. CSRF Attack Detection
def detect_csrf(request):
    # Check for missing or incorrect referer header
    referer = request.headers.get('Referer', '')
    if not referer or not referer.startswith('http://127.0.0.1:5000'):
        # In a real app, check against allowed domains
        return True
    
    # Check for suspicious form submissions without CSRF token
    if request.method == 'POST' and 'csrf_token' not in request.form:
        return True
    
    return False
# 4. Server-Side Request Forgery (SSRF) Detection
def detect_ssrf(input_text):
    ssrf_patterns = [
        r"https?://localhost",
        r"https?://127\.0\.0\.1",
        r"https?://0\.0\.0\.0",
        r"https?://169\.254\.",
        r"https?://192\.168\.",
        r"https?://10\.",
        r"https?://172\.(1[6-9]|2[0-9]|3[0-1])\.",
        r"file:///",
        r"dict://"
    ]
    for pattern in ssrf_patterns:
        if re.search(pattern, input_text, re.IGNORECASE):
            return True
    return False

# 5. Authentication Bypass Detection
def detect_ssrf(input_string):
    """Detect SSRF attempts"""
    ssrf_patterns = [
        "localhost", "127.0.0.1", "0.0.0.0", "169.254", "192.168", "10.",
        "172.16", "file://", "dict://", "gopher://", "ftp://", "http://internal",
        "https://internal", "http://localhost", "https://localhost"
    ]
    return any(pattern.lower() in input_string.lower() for pattern in ssrf_patterns)

def detect_auth_bypass(input_string):
    """Detect authentication bypass attempts"""
    bypass_patterns = [
        "admin' --", "' OR '1'='1", "' OR 1=1", "OR 1=1", "admin' #",
        "admin'/*", "' OR '1'='1' --", "' OR '1'='1' /*", "' OR 'x'='x",
        "' OR ''='", "1' OR '1' = '1", "' OR 1 -- -", "' OR 'x'='x';--"
    ]
    return any(pattern.lower() in input_string.lower() for pattern in bypass_patterns)
def detect_token_exfiltration(input_string):
    """Detect API token exfiltration attempts"""
    token_patterns = [
        "api_key", "apikey", "token", "auth_token", "jwt", "bearer",
        "oauth", "access_token", "secret_key", "private_key",
        "AKIA", "sk_live", "pk_live", "ASIA", "ghp_", "sk-"  # AWS, Stripe, GitHub and OpenAI key patterns
    ]
    return any(pattern.lower() in input_string.lower() for pattern in token_patterns)

# 7. Brute Force Attack Detection (IP-based rate limiting)
def detect_brute_force(request, rate_limit_threshold=5):
    ip_address = request.remote_addr
    current_time = time.time()
    
    # Create in-memory store if it doesn't exist
    if not hasattr(detect_brute_force, 'ip_attempts'):
        detect_brute_force.ip_attempts = {}
    
    # Initialize or update IP record
    if ip_address not in detect_brute_force.ip_attempts:
        detect_brute_force.ip_attempts[ip_address] = {
            'count': 1,
            'first_attempt': current_time
        }
        return False
    
    # Check time window (5 minutes)
    time_window = 300  # 5 minutes in seconds
    record = detect_brute_force.ip_attempts[ip_address]
    
    if current_time - record['first_attempt'] > time_window:
        # Reset if outside time window
        record['count'] = 1
        record['first_attempt'] = current_time
        return False
    else:
        # Increment counter
        record['count'] += 1
        if record['count'] > rate_limit_threshold:
            return True
        return False
if __name__ == "__main__":
    if not os.path.exists(DATABASE):
        init_db()
    socketio.run(app, debug=True)
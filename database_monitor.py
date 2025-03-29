import re
import sqlite3
from flask import g

def monitor_database_activity(query, username):
    suspicious = False
    reason = ""
    
    # Check for queries that return large amounts of data
    if re.search(r"SELECT\s+\*", query, re.IGNORECASE):
        suspicious = True
        reason = "Full table retrieval detected"
    
    # Check for queries that access multiple tables at once
    if query.lower().count("from") > 1:
        suspicious = True
        reason = "Multi-table query detected"
    
    # Check for queries outside normal user access patterns
    # Example: admin user should only access admin tables
    if username != "admin" and re.search(r"admin|config|settings", query, re.IGNORECASE):
        suspicious = True
        reason = "Accessing unauthorized tables"
    
    return suspicious, reason

def track_database_size_changes():
    """Monitor sudden changes in database size which could indicate mass extraction"""
    db = getattr(g, "_database", None)
    cursor = db.cursor()
    
    # Get table sizes
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    
    size_info = {}
    for table in tables:
        table_name = table[0]
        cursor.execute(f"SELECT COUNT(*) FROM {table_name};")
        row_count = cursor.fetchone()[0]
        size_info[table_name] = row_count
    
    return size_info
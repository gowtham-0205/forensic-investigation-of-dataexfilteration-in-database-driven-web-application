import re
from flask import request

def analyze_network_traffic(request):
    # Extract headers and request data
    headers = dict(request.headers)
    cookies = dict(request.cookies)
    payload = request.form.to_dict() if request.form else {}
    
    suspicious_indicators = []
    
    # Check for unusual User-Agent strings
    if "User-Agent" in headers:
        if re.search(r"(curl|wget|python-requests|Go-http-client)", headers["User-Agent"]):
            suspicious_indicators.append("Unusual User-Agent detected")
    
    # Check for large data in cookies
    for name, value in cookies.items():
        if len(value) > 100:  # Arbitrary threshold
            suspicious_indicators.append(f"Large cookie value: {name}")
    
    # Check for potential data in referer
    if "Referer" in headers and "?" in headers["Referer"]:
        suspicious_indicators.append("Data in Referer parameter")
    
    return suspicious_indicators

def check_data_volume(request_data, threshold=1000):
    """Check if the request data exceeds normal volume thresholds"""
    total_data_size = 0
    
    # Calculate total size of form data
    if request.form:
        for key, value in request.form.items():
            total_data_size += len(key) + len(value)
    
    # Check file uploads if any
    if request.files:
        for key, file in request.files.items():
            content = file.read()
            total_data_size += len(content)
            file.seek(0)  # Reset file pointer
    
    return total_data_size > threshold
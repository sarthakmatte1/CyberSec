import os

def is_malicious_file(filename):
    filename = filename.lower().strip()

    blocked_ext = [
        ".exe",
        ".bat",
        ".cmd",
        ".js",
        ".vbs",
        ".scr",
        ".msi"
    ]

    suspicious_words = [
        "hack",
        "payload",
        "virus",
        "trojan",
        "malware",
        "keylogger"
    ]

    # Direct dangerous extension
    for ext in blocked_ext:
        if filename.endswith(ext):
            return True

    # Double extension check
    dangerous_patterns = [
        ".pdf.exe",
        ".doc.exe",
        ".docx.exe"
    ]

    for p in dangerous_patterns:
        if p in filename:
            return True

    # Suspicious words
    for word in suspicious_words:
        if word in filename:
            return True

    return False
from datetime import datetime

def add_log(db, email, action, ip):
    db.security_logs.insert_one({
        "email": email,
        "action": action,
        "ip": ip,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
from utils.mailer import send_email

def send_admin_alert(app, admin_email, subject, message):
    if admin_email:
        send_email(
            app,
            admin_email,
            subject,
            message
        )
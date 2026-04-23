from flask_mail import Mail, Message

mail = Mail()

def send_email(app, to_email, subject, body):
    with app.app_context():
        msg = Message(
            subject=subject,
            sender=app.config["MAIL_USERNAME"],
            recipients=[to_email]
        )
        msg.body = body
        mail.send(msg)
import os
from flask_mail import Mail, Message
from flask import Flask

app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')  # Your email address
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')  # Your email app password
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)

def send_email_alert(alert_message):
    print(f"Sending email alert with the following message:\n{alert_message}")  # Debugging line
    with app.app_context():  # Create an application context for Flask-Mail
        msg = Message(
            subject='AI Honeypot Alert',
            sender=os.getenv('EMAIL_USER'),
            recipients=['denveremily520@gmail.com']  # Replace with your target email address
        )
        msg.body = alert_message
        try:
            mail.send(msg)
            print("Email sent successfully!")
        except Exception as e:
            print(f"Error sending email: {e}")

if __name__ == "__main__":
    # Test sending an email alert
    send_email_alert('Test alert from AI honeypot!')

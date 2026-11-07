
import os
import smtplib
from datetime import datetime
from email.message import EmailMessage
from dotenv import load_dotenv
from database import add_event

load_dotenv()


def send_email_alert(file_path, status):

    if os.getenv("MAIL_ENABLED", "false").lower() != "true":
        return

    sender = os.getenv("MAIL_SENDER")
    password = os.getenv("MAIL_PASSWORD")
    receiver = os.getenv("MAIL_RECEIVER")

    if not all([sender, password, receiver]):
        print("Email settings are incomplete.")
        return

    message = EmailMessage()

    message["Subject"] = f"FileGuard Security Alert: {status}"
    message["From"] = sender
    message["To"] = receiver

    message.set_content(
        f"""
File Integrity Monitoring System

Security Event: {status}
File: {file_path}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Please investigate this file modification or deletion.
"""
    )

    try:
        with smtplib.SMTP(
            os.getenv("SMTP_SERVER", "smtp.gmail.com"),
            int(os.getenv("SMTP_PORT", "587"))
        ) as server:

            server.starttls()
            server.login(sender, password)
            server.send_message(message)

        print("Email security alert sent!")

    except Exception as error:
        print("Email notification failed:", error)


def generate_alert(file_path, status):

    os.makedirs("logs", exist_ok=True)

    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    message = (
        f"{current_time} | "
        f"ALERT: {file_path} | "
        f"STATUS: {status}\n"
    )

    with open("logs/security_events.log", "a") as log:
        log.write(message)

    add_event(file_path, status)

    print("SECURITY ALERT:", status, file_path)

    send_email_alert(file_path, status)

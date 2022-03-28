from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os


def send_email(email, verificationString, type):
    if type == 'verify':
        message = Mail(
            from_email=os.environ.get('SENDGRID_EMAIL'),
            to_emails=email,
            subject='Verify your email',
            html_content=f'Thank you for signing up! Click here to <a href="http://localhost:5000/api/verify-email?verificationString={verificationString}">verify your email</a>')
    
    elif type == 'reset':
        message = Mail(
            from_email=os.environ.get('SENDGRID_EMAIL'),
            to_emails=email,
            subject='Reset your password',
            html_content=f'Click here to <a href="http://localhost:5000/api/users/{verificationString}/reset-password">reset your password</a>')

    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'),)
        response = sg.send(message)

    except Exception as e:
        print(e)

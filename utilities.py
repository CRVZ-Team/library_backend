from datetime import datetime
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os
from string import ascii_letters, digits
from random import choice


def send_email(email, type, invoice=None, verificationString=None):
    if type == 'verify':
        message = Mail(
            from_email=os.environ.get('SENDGRID_EMAIL'),
            to_emails=email,
            subject='Verify your email',
            html_content=f'Thank you for signing up! Click here to <a href="http://localhost:3000/verify-email/{verificationString}">verify your email</a>')
    
    elif type == 'reset':
        message = Mail(
            from_email=os.environ.get('SENDGRID_EMAIL'),
            to_emails=email,
            subject='Reset your password',
            html_content=f'Click here to <a href="http://localhost:3000/reset-password/{verificationString}">reset your password</a>')

    elif type == 'invoice':
        total_price = "{:.2f}".format(invoice.total_price)
        message = Mail(
            from_email=os.environ.get('SENDGRID_EMAIL'),
            to_emails=email,
            subject="Mrs. Who's Library Purchase Invoice",
            html_content=f""""<header><h1>Invoice</h1></header>
            <article><h1>Recipient</h1><address><p>{email}</p></address>
            <table class="meta">
            <tr><th><span>Invoice #</span></th><td><span>{invoice.id}</span></td></tr>
            <tr><th><span>Date</span></th><td><span>{datetime.now().strftime("%m/%d/%Y")}</span></td></tr>
			<tr><th><span>Amount</span></th><td><span id="prefix">dkk </span><span>{total_price}</span></td></tr>
			</table>""")
    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'),)
        response = sg.send(message)

    except Exception as e:
        print(e)

def str_random(length):
    '''Generate a random string using range [a-zA-Z0-9].'''
    chars = ascii_letters + digits
    return ''.join([choice(chars) for i in range(length)])
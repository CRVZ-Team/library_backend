import os
import jwt
import bcrypt
from uuid import uuid4
from utilities import *
from bottle.ext import sqlalchemy
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from bottle import get, install, post, put, route, run, template, request, response, static_file, redirect

from db import User

from dotenv import load_dotenv
load_dotenv()

Base = declarative_base()

engine = create_engine('mysql://ofutjb17rq2pjfgu:ev7q5q6uee55p1uu@spryrr1myu6oalwl.chr7pe7iynqr.eu-west-1.rds.amazonaws.com:3306/pqbzhf5qjts9on9i')
create_session = sessionmaker(bind=engine)

plugin = sqlalchemy.Plugin(
    engine,
    Base.metadata,
    keyword='db',
    create=True,
    commit=True,
    use_kwargs=False
)

install(plugin)

secret = os.environ.get('JWT_SECRET')

@get('/')
def index():
    return 

@post('/api/login')
def _():
    try:
        email = request.forms.get('email')
        password = request.forms.get('password')
        session = create_session()
        user = session.query(User).filter_by(email=email).first()
        if not user:
            return {'status': 'error', 'message': 'Invalid email'}
        
        isCorrect = bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8'))
        if not isCorrect:
            return {'status': 'error', 'message': 'Invalid password'}
        # add more variables token
        token = jwt.encode({'id': user.id}, secret, algorithm='HS256')
        if not token:
            return {'status': 'error'}
        return {'status': 'success', 'token': token}
    except Exception as e:
        return {'status': 'error', 'message': 'Invalid email or password'}

@post('/api/signup')
def _():
    try:
        email = request.forms.get('email')
        password = request.forms.get('password')
        session = create_session()
        user = session.query(User).filter_by(email=email).first()
        if user:
            return {'status': 'error', 'message': 'User already exists'}
        verificationString = str(uuid4())
        passwordHash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = User(email, passwordHash, verificationString)
        session.add(user)
        session.commit()

        send_email(email, verificationString, 'verify')
        # add more variables token
        token = jwt.encode({'id': user.id}, secret, algorithm='HS256')
        return {'status': 'success', 'token': token}
    except Exception as e:
        print(e)
        return {'status': 'error', 'message': 'Error sending email'}

@put('/api/verify-email')
def _():
    verificationString = request.forms.get('verificationString')
    session = create_session()
    user = session.query(User).filter_by(verification_string=verificationString).first()
    
    if not user:
        return {'status': 'error', 'message': 'Invalid verification string'}
    
    user.is_verified = True
    user.verification_string = ''
    session.commit()

    token = jwt.encode({'id': user.id}, secret, algorithm='HS256')  

    if not token:
        return {'status': 'error'}
    return {'status': 'success', 'token': token}

@put('/api/users/<passwordResetCode>/reset-password')
def _(passwordResetCode):
    try:
        newPassword = request.forms.get('newPassword')
        session = create_session()
        user = session.query(User).filter_by(password_reset_code=passwordResetCode).first()
        if not user:
            return {'status': 'error', 'message': 'Invalid password reset code'}

        user.password = bcrypt.hashpw(newPassword.encode('utf-8'), bcrypt.gensalt())
        user.password_reset_code = ''
        session.commit()
        
        return {'status': 'success'}
    except Exception as e:
        print(e)
        return {'status': 'error', 'message': 'Error resetting password'}

@put('/api/forgot-password/<email>')
def _(email):
    try:
        session = create_session()
        user = session.query(User).filter_by(email=email).first()
        if not user:
            return {'status': 'error', 'message': 'Invalid email'}
        passwordResetCode = str(uuid4())
        user.password_reset_code = passwordResetCode
        session.commit()
        send_email(email, passwordResetCode, 'reset')
        return {'status': 'success'}

    except Exception as e:
        return {'status': 'error', 'message': 'Error sending email'}

run(host='127.0.0.1', port=8000, debug=True, reloader=True, server='paste')
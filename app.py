import os
import jwt
import json
import bcrypt
import decimal
from uuid import uuid4
from utilities import *
from bottle.ext import sqlalchemy
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from bottle import get, install, post, put, route, run, template, request, response, static_file, redirect

from db import User, Book, Subscription, BookGenre, UserBook, Review, Coeficient

from dotenv import load_dotenv
load_dotenv()

Base = declarative_base()

engine = create_engine(os.getenv("DATABASE_URL"))
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

def default_json(t):
    if type(t) == decimal.Decimal:
        return "{:.2f}".format(t)
    return f'{t}'

class EnableCors(object):
    name = 'enable_cors'
    api = 2

    def apply(self, fn, context):
        def _enable_cors(*args, **kwargs):
            # set CORS headers
            response.headers['Access-Control-Allow-Origin'] = 'http://localhost:3000'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Origin, Accept, Content-Type, X-Requested-With, X-CSRF-Token'

            if request.method != 'OPTIONS':
                # actual request; reply with the actual response
                return fn(*args, **kwargs)

        return _enable_cors

install(EnableCors())

secret = os.environ.get('JWT_SECRET')

@get('/')
def index():
    return 

@route('/api/login', method=['OPTIONS', 'POST'])
def _():
    try:
        payload = json.loads(request.body.read())
        email = payload['email']
        print(email)
        password = payload['password']
        print(password)
        session = create_session()
        user = session.query(User).filter_by(email=email).first()
        print(user)
        if not user:
            print("User not found")
            response.status = 401
            return response
        
        isCorrect = bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8'))
        if not isCorrect:
            response.status = 401
            return response
        # add more variables token
        token = jwt.encode({'id': user.id}, secret, algorithm='HS256')
        if not token:
            response.status = 401
            return response
        response.status = 200
        return {'token': token}
    except Exception as e:
        return {'status': 'error', 'message': 'Invalid email or password'}

@route('/api/signup', method=['OPTIONS', 'POST'])
def _():
    try:
        payload = json.loads(request.body.read())
        email = payload['email']
        print(email)
        password = payload['password']
        print(password)
        session = create_session()
        user = session.query(User).filter_by(email=email).first()
        if user:
            response.status = 401
            return response
        verificationString = str(uuid4())
        passwordHash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = User(email, passwordHash, verificationString)
        print(user)
        session.add(user)
        session.commit()

        send_email(email, verificationString, 'verify')
        # add more variables token
        token = jwt.encode({'id': user.id}, secret, algorithm='HS256')
        response.status = 200
        return {'token': token}
    except Exception as e:
        print(e)
        response.status = 500
        return {'message': 'Error sending email'}

@route('/api/verify-email', method=['OPTIONS', 'PUT'])
def _():
    payload = json.loads(request.body.read())
    verificationString = payload['verificationString']
    session = create_session()
    user = session.query(User).filter_by(verification_string=verificationString).first()
    
    if not user:
        response.status = 401
        return {'message': 'Invalid verification string'}
    
    user.is_verified = True
    user.verification_string = ''
    session.commit()

    token = jwt.encode({'id': user.id}, secret, algorithm='HS256')  

    if not token:
        response.status = 500
        return response
    response.status = 200
    return response

@route('/api/users/<passwordResetCode>/reset-password', method=['OPTIONS', 'PUT'])
def _(passwordResetCode):
    try:
        payload = json.loads(request.body.read())
        newPassword = payload['newPassword']
        session = create_session()
        user = session.query(User).filter_by(password_reset_code=passwordResetCode).first()
        if not user:
            response.status = 401
            return {'message': 'Invalid password reset code'}

        user.password = bcrypt.hashpw(newPassword.encode('utf-8'), bcrypt.gensalt())
        user.password_reset_code = ''
        session.commit()
        response.status = 200
        return response
    except Exception as e:
        print(e)
        response.status = 500
        return {'message': 'Error resetting password'}

@route('/api/forgot-password/<email>', method=['OPTIONS', 'PUT'])
def _(email):
    try:
        session = create_session()
        user = session.query(User).filter_by(email=email).first()
        if not user:
            response.status = 401
            return {'message': 'Invalid email'}
        passwordResetCode = str(uuid4())
        user.password_reset_code = passwordResetCode
        session.commit()
        send_email(email, passwordResetCode, 'reset')
        response.status = 200
        return response

    except Exception as e:
        response.status = 500
        return response


@route('/api/users/<id>', method=['OPTIONS', 'GET'])


@route('/api/book/<id>', method=['OPTIONS', 'GET'])
def _(id):
    session = create_session()
    book = session.query(Book).filter_by(id=id).first()
    if not book:
        response.status = 404
        return response
    # get reviews for the book
    reviews = session.query(Review).filter_by(book_id=id).all()
    # get coeficient for the book price
    coeficient = session.query(Coeficient).first()
    subscriptions = {"month": book.price * coeficient.month, "year": book.price * coeficient.year}
    data = {'book': book.to_dict(), 'subscriptions': subscriptions, 'reviews': [review.to_dict() for review in reviews]}
    session.close()
    response.status = 200
    return json.dumps(data, default=default_json)


@route('/api/books', method=['OPTIONS', 'GET'])
def _():
    session = create_session()
    books = session.query(Book).all()
    response.status = 200
    return [book.to_dict() for book in books]


# FEATURE for ADMIN (add book)
@route('/api/books', method=['OPTIONS', 'POST'])
def _():
    try:
        payload = json.loads(request.body.read())
        title = payload['title']
        author = payload['author']
        description = payload['description']
        image_url = payload['image_url']
        session = create_session()
        book = Book(title, author, description, image_url)
        session.add(book)
        session.commit()
        response.status = 201
        return response
    except Exception as e:
        response.status = 500
        return {'message': 'Error creating book'}

# FEATURE for ADMIN (delete book)
@route('/api/book/<id>', method=['OPTIONS', 'DELETE'])
def _(id):
    session = create_session()
    book = session.query(Book).filter_by(id=id).first()
    if not book:
        response.status = 404
        return response
    session.delete(book)
    session.commit()
    response.status = 200
    return response

@route('/api/book/<id>', method=['OPTIONS', 'PUT'])
def _(id):
    try:
        payload = json.loads(request.body.read())
        title = payload['title']
        author = payload['author']
        description = payload['description']
        image_url = payload['image_url']
        session = create_session()
        book = session.query(Book).filter_by(id=id).first()
        if not book:
            response.status = 404
            return response
        book.title = title
        book.author = author
        book.description = description
        book.image_url = image_url
        session.commit()
        response.status = 200
        return response
    except Exception as e:
        response.status = 500
        return {'message': 'Error updating book'}

@route('/api/users/<id>', method=['OPTIONS', 'GET'])
def _(id):
    session = create_session()
    user = session.query(User).filter_by(id=id).first()
    if not user:
        response.status = 404
        return response
    response.status = 200
    return user.to_dict()


    

if os.environ.get('APP_LOCATION') == 'heroku':
    run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
else:
    run(host='localhost', port=8080, debug=True, reloader=True, server='paste')
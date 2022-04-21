from asyncio import protocols
import os
from typing import final
from xmlrpc.client import Boolean
import jwt
import json
import bcrypt
import decimal
import unittest
from boddle import boddle
from uuid import uuid4
from utilities import *
from bottle.ext import sqlalchemy
from sqlalchemy import create_engine, Column, Integer, String, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from bottle import get, install, post, put, route, run, template, request, response, static_file, redirect

from db import User, Book, Subscription, BookGenre, UserBook, Review, Coeficient, Genre, Invoice, InvoiceBook

from dotenv import load_dotenv
load_dotenv()

Base = declarative_base()

engine = create_engine(os.getenv("DATABASE_URL"))
create_session = sessionmaker(bind=engine)

# Create the SQLAlchemy pluggin connected to the database
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

# Handle CORS policy for the frontend
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
    return "Hello"

# LOGIN
@route('/api/login', method=['OPTIONS', 'POST'])
def login():
    try:
        session = create_session()
        payload = json.loads(request.body.read())
        email = payload['email']
        password = payload['password']

        user = session.query(User).filter_by(email=email).first()

        if not user:
            response.status = 401
            return response
        
        isCorrect = bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8'))
        if not isCorrect:
            response.status = 401
            return response
        
        # add more variables token
        token = jwt.encode({'id': user.id, 'email': user.email, 'verified': user.is_verified, 'admin': user.is_admin}, secret, algorithm='HS256')
        if not token:
            response.status = 401
            return response
        
        response.status = 200
        return {'token': token}
    except Exception as e:
        return {'status': 'error', 'message': 'Invalid email or password'}
    finally:
        session.close()

# Sign up
@route('/api/signup', method=['OPTIONS', 'POST'])
def signup():
    try:
        payload = json.loads(request.body.read())
        email = payload['email']
        password = payload['password']

        session = create_session()
        user = session.query(User).filter_by(email=email).first()
        if user:
            response.status = 401
            return response

        verificationString = str(uuid4())
        passwordHash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = User(email, passwordHash, verificationString)
        session.add(user)
        session.commit()

        send_email(email, verificationString, 'verify')

        # add more variables token
        token = jwt.encode({'id': user.id, 'email': user.email, 'verified': user.is_verified, 'admin': user.is_admin}, secret, algorithm='HS256')
        response.status = 200
        return {'token': token}
    except Exception as e:
        response.status = 500
        return {'message': 'Error sending email'}
    finally:
        session.close()


# Verify email
@route('/api/verify-email', method=['OPTIONS', 'PUT'])
def _():
    try:
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

        token = jwt.encode({'id': user.id, 'email': user.email, 'verified': user.is_verified, 'admin': user.is_admin}, secret, algorithm='HS256')  

        if not token:
            response.status = 500
            return response

        response.status = 200
        return {'token': token}
    except Exception as e:
        response.status = 500
        return response
    finally:
        session.close()


# Reset the password
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
        response.status = 500
        return {'message': 'Error resetting password'}
    finally:
        session.close()


# Forgot password
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
    finally:
        session.close()


@route('/api/users/<id>', method=['OPTIONS', 'GET'])


# Single book page
@route('/api/book/<id>', method=['OPTIONS', 'GET'])
def book(id):
    try:
        session = create_session()
        book = session.query(Book).filter_by(id=id).first()
        if not book:
            response.status = 404
            return response

        # get genres for the book\
        genre_ids = session.query(Genre).join(BookGenre).filter_by(book_id=id).all()
        genres = ", ".join([genre.type for genre in genre_ids])

        # get reviews for the book
        reviews_query = session.query(Review, User.email).filter(Review.user_id == User.id).filter(Review.book_id==id).filter(Review.approved == True).all()
        reviews	= [{'comment': review[0].to_dict(), 'user': review[1]} for review in reviews_query]

        # get coeficient for the book price
        coeficient = session.query(Coeficient).first()

        #get subscribers for the book
        subscriptions = {"month": book.price * coeficient.month, "year": book.price * coeficient.year}

        data = {'book': book.to_dict(), 'genres': genres, 'subscriptions': subscriptions, 'reviews': reviews}
        response.status = 200
        return json.dumps(data, default=default_json)
    except Exception as e:
        response.status = 500
        return response
    finally:
        session.close()

# Route for getting the books
@route('/api/books', method=['OPTIONS', 'GET'])
def books():
    try:
        session = create_session()
        books = session.query(Book).all()

        response.status = 200
        return json.dumps([book.to_dict() for book in books], default=default_json)
    except Exception as e:
        response.status = 500
        return response
    finally:
        session.close()


# FEATURE for ADMIN (add book)
@route('/api/books', method=['OPTIONS', 'POST'])
def _():
    try:
        payload = json.loads(request.body.read())
        title = payload['title']
        author = payload['author']
        description = payload['description']
        image_url = payload['image_url']
        price = payload['price']
        genres = payload['genres']
    
        session = create_session()
        book = Book(title, author, description, image_url, price)
        # genres

        session.add(book)
        session.commit()

        response.status = 201
        return response
    except Exception as e:
        response.status = 500
        return {'message': 'Error creating book'}
    finally:
        session.close()

# FEATURE for ADMIN (delete book)
@route('/api/books/<id>', method=['OPTIONS', 'DELETE'])
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

@route('/api/books/<id>', method=['OPTIONS', 'PUT'])
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


# 
@route('/api/users/<id>', method=['OPTIONS', 'GET'])
def _(id):
    session = create_session()
    user = session.query(User).filter_by(id=id).first()
    if not user:
        response.status = 404
        return response
    response.status = 200
    return user.to_dict()


# Reviews and comments for the book
@route('/api/comment', method=['OPTIONS', 'POST'])
def rewiew():
    try:
        session = create_session()
        payload = json.loads(request.body.read())
        rating = payload['rating']
        comment = payload['comment']
        book_id = payload['book_id']
        user_id = payload['user_id']

        review = Review(book_id=book_id, user_id=user_id, comment=comment, rating=rating, approved=False)
        session.add(review)
        session.commit()

        response.status = 201
        return "success"
    except Exception as e:
        print(e)
        response.status = 500
        return response
    finally:
        session.close()

    
# Filters for the books
@route('/api/filters/authors', method=['OPTIONS', 'GET'])
def filters():
    try:
        session = create_session()

        #query authors
        authors_data = session.query(Book).all()
        authors = [{'name': book.author} for book in authors_data]

    #query year span
    # max_year = session.query(func.max(Book.year)).first()[0]
    # min_year = session.query(func.min(Book.year)).first()[0]

    # year_span = [{"max": max_year, "min": min_year}]
        years = []
        years_data = session.query(Book).all()
        for book in years_data:
            if book.year not in years:
                years.append(book.year)


        years.sort()
            
        print(years)

        #query genres
        genres_data = session.query(Genre).all()
        genres = [{'name': genre.type} for genre in genres_data]

        #create general dict
        data =  [{"authors": authors}, {"year_span": years}, {"genres": genres}]
        response.status = 200
        return json.dumps(data, default=default_json)
    except Exception as e:
        response.status = 500
        return response
    finally:
        session.close()


@route ('/api/filter/books', method=['OPTIONS', 'POST'])
def filter_books():
    try:
        session = create_session()
        payload = json.loads(request.body.read())
        authors = payload['authors']
        years = payload['years']
        genres = payload['genres']

        print(authors, years, genres)

        #query books
        if len(genres) != 0:
            books_ids = session.query(BookGenre.book_id).join(Genre).filter(Genre.type.in_(genres)).all()
            books_ids = [book[0] for book in books_ids]
        else:
            books_ids = []
        
        books_data = [] 
        print(books_ids)

        if len(authors) != 0 and len(years) != 0 and len(books_ids) != 0:
            books_data = session.query(Book).filter(Book.author.in_(authors)).filter(Book.year.in_(years)).filter(Book.id.in_(books_ids)).all()
        elif len(authors) != 0 and len(years) != 0:
            books_data = session.query(Book).filter(Book.author.in_(authors)).filter(Book.year.in_(years)).all()
        elif len(authors) != 0 and len(books_ids) != 0:
            books_data = session.query(Book).filter(Book.author.in_(authors)).filter(Book.id.in_(books_ids)).all()
        elif len(years) != 0 and len(books_ids) != 0:
            books_data = session.query(Book).filter(Book.year.in_(years)).filter(Book.id.in_(books_ids)).all()
        elif len(authors) != 0:
            books_data = session.query(Book).filter(Book.author.in_(authors)).all()
        elif len(years) != 0:
            books_data = session.query(Book).filter(Book.year.in_(years)).all()
        elif len(books_ids) != 0:
            books_data = session.query(Book).filter(Book.id.in_(books_ids)).all()
        else:
            books_data = session.query(Book).all()

        return json.dumps([book.to_dict() for book in books_data], default=default_json)
    except Exception as e:
        print(e)
        response.status = 500
        return response
    finally:
        session.close()


# Handle payment
@route('/api/invoice', method=['OPTIONS', 'POST'])
def invoice():
    try:
        session = create_session()
        payload = json.loads(request.body.read())
        user_id = payload['user_id']
        date = payload['date']
        total_price = payload['total_price']
        books = payload['books']
        invoice = Invoice(user_id=user_id, date=date, total_price=total_price)
        invoice_book = []
        user_book = []
        # TRANSACTION
        with session.begin() as session:
            invoice_id = session.add(invoice)
            for book in books:
                user_book.append(UserBook(user_id=user_id, book_id=book['id'], subs_id=book['subs_id'], init_date=book['init_date'], exp_date=book['exp_date']))
                invoice_book.append(InvoiceBook(book_id=book['id'], invoice_id=invoice_id))
            session.add_all(invoice_book)
            session.add_all(user_book)
        response.status = 201
        return "success"
    except Exception as e:
        print(e)
        response.status = 500
        return response
    finally:
        session.close()
        
if os.environ.get('APP_LOCATION') == 'heroku':
    run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
else:
    run(host='localhost', port=8080, debug=True, reloader=True, server='paste')


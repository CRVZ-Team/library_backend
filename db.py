from bottle.ext import sqlalchemy
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

def to_dict(self):
    return {c.name: getattr(self, c.name, None)
            for c in self.__table__.columns}
Base.to_dict = to_dict

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String(80), unique=True)
    password = Column(String(60))
    is_verified = Column(Boolean)
    verification_string = Column(String(50))
    password_reset_code = Column(String(50))
    is_admin = Column(Boolean)

    def __init__(self, email, password, verification_string=None, is_verified=False,  password_reset_code=None , is_admin=False):
        self.email = email
        self.password = password
        self.is_verified = is_verified
        self.verification_string = verification_string
        self.password_reset_code = password_reset_code
        self.is_admin = is_admin

    def __repr__(self):
        return '<User %r>' % self.id


class Book(Base):
    __tablename__ = 'books'
    id = Column(Integer, primary_key=True)
    image_url = Column(String(100))
    title = Column(String(80))
    author = Column(String(80))
    year = Column(Integer)
    price = Column(Float(9,2))
    description = Column(String(1000))
    avg_rating = Column(Float(2,1))
    quantity = Column(Integer)

    def __init__(self, image_url, title, author, year, price, description, avg_rating, quantity):
        self.image_url = image_url
        self.title = title
        self.author = author
        self.year = year
        self.price = price
        self.description = description
        self.avg_rating = avg_rating
        self.quantity = quantity

    def __repr__(self):
        return '<Book %r>' % self.title



class Subscription(Base):
    __tablename__ = 'subscriptions'
    id = Column(Integer, primary_key=True)
    type = Column(String(15))

    def __init__(self, type):
        self.type = type

    def __repr__(self):
        return '<Subscriptions %r>' % self.id


class Review(Base):
    __tablename__ = 'reviews'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    book_id = Column(Integer, ForeignKey('books.id'))
    title = Column(String(20))
    comment = Column(String(500))
    rating = Column(Integer)
    approved = Column(Boolean)
    

    def __init__(self, user_id, book_id, title, comment, rating, approved):
        self.user_id = user_id
        self.book_id = book_id
        self.title = title
        self.comment = comment
        self.rating = rating
        self.approved = approved

    def __repr__(self):
        return '<Review %r>' % self.id

class Genre(Base):
    __tablename__ = 'genres'
    id = Column(Integer, primary_key=True)
    type = Column(String(20))

    def __init__(self, type):
        self.type = type

    def __repr__(self):
        return '<Genre %r>' % self.id

class BookGenre(Base):
    __tablename__ = 'book_genre'
    id = Column(Integer, primary_key=True)
    book_id = Column(Integer, ForeignKey('books.id'))
    genre_id = Column(Integer, ForeignKey('genres.id'))

    def __init__(self, book_id, genre_id):
        self.book_id = book_id
        self.genre_id = genre_id

class Invoice(Base):
    __tablename__ = 'invoices'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    date = Column(DateTime)
    total_price = Column(Float(10,2))

    def __init__(self, user_id, date, total_price):
        self.user_id = user_id
        self.date = date
        self.total_price = total_price

    def __repr__(self):
        return '<Invoice %r>' % self.id

class InvoiceBook(Base):
    __tablename__ = 'invoice_book'
    id = Column(Integer, primary_key=True)
    invoice_id = Column(Integer, ForeignKey('invoices.id'))
    book_id = Column(Integer, ForeignKey('books.id'))

    def __init__(self, invoice_id, book_id):
        self.invoice_id = invoice_id
        self.book_id = book_id
    
    def __repr__(self):
        return '<InvoiceBook %r>' % self.id

class Coeficient(Base):
    __tablename__ = 'coeficient'
    id = Column(Integer, primary_key=True)
    month = Column(Float(6,3))
    year = Column(Float(6,3))

    def __init__(self, month, year):
        self.month = month
        self.year = year

class UserBook(Base):
    __tablename__ = 'user_book'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    book_id = Column(Integer, ForeignKey('books.id'))
    subs_id = Column(Integer, ForeignKey('subscriptions.id'))
    init_date = Column(DateTime)
    exp_date = Column(DateTime)

    def __init__(self, user_id, book_id, subs_id, init_date, exp_date):
        self.user_id = user_id
        self.book_id = book_id
        self.subs_id = subs_id
        self.init_date = init_date
        self.exp_date = exp_date
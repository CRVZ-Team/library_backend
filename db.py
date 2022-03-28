from bottle.ext import sqlalchemy
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String(80), unique=True)
    password = Column(String(60))
    is_verified = Column(Boolean)
    verification_string = Column(String(17))
    password_reset_code = Column(String(17))
    is_admin = Column(Boolean)

    def __init__(self, email, password, verification_string=None, is_verified=False,  password_reset_code=None , is_admin=False):
        self.email = email
        self.password = password
        self.is_verified = is_verified
        self.verification_string = verification_string
        self.password_reset_code = password_reset_code
        self.is_admin = is_admin

    def __repr__(self):
        return '<User %r>' % self.username


#class ...
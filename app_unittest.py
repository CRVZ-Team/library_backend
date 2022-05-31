import os
import app
import jwt
import json
import unittest
from boddle import boddle
from datetime import datetime, timedelta

secret = os.environ.get('JWT_SECRET')

filters = [
    {"authors": [{"name": "Bram Stoker"}, {"name": "F. Scott Fitzgerald"}, {"name": "Friedrich Nietzsche"}, {"name": "Hans Rosling"}, {"name": "Haruki Murakami"},
                    {"name": "J.K. Rowling"}, {"name": "Jane Austen"}, {"name": "Louisa May Alcott"}, {"name": "Mark Manson"}, {"name": "Mary Shelley"}, 
                    {"name": "Oscar Wilde"}, {"name": "Yuval Noah Harari"} ]
    }, 
    {"year_span": [1816, 1818, 1868, 1897, 2004, 2005, 2013, 2014, 2015, 2016, 2017, 2018, 2019]}, 
    {"genres": [{"name": "Drama"}, {"name": "Romance"}, {"name": "Horror"}, {"name": "Sci-fi"}, {"name": "Comedy"}, {"name": "Thriller"}, {"name": "Detective"}, 
                    {"name": "Fiction"}, {"name": "Children's book"}, {"name": "Biography"}, {"name": "Non-fiction"}, {"name": "Self-help"}, {"name": "Fantasy"}]}
    ]

class TestLogin(unittest.TestCase):       
    def test_successfull_login(self):
        with boddle(body="{\"email\": \"test\", \"password\": \"test\"}"):
            token_payload = jwt.decode(app.login()['token'], secret, algorithms=['HS256'])
            self.assertEqual(token_payload['email'], 'test')
            self.assertEqual(token_payload['id'], 1)
            self.assertEqual(token_payload['admin'], 1)

    def test_wrong_password(self):
        with boddle(body="{\"email\": \"test\", \"password\": \"test1\"}"):
            self.assertEqual(app.login(), {'error': 'Invalid credentials'})
        
    def test_wrong_email(self):
        with boddle(body="{\"email\": \"test1\", \"password\": \"test\"}"):
            self.assertEqual(app.login(), {'error': 'Invalid credentials'})	

    def test_exception_login(self):
        with boddle(body="{\"password\": \"test\"}"):
            self.assertEqual(app.login(), 'error')


class TestGetBooks(unittest.TestCase):
    def test_get_books(self):
        self.assertEqual(len(json.loads(app.books())), 15)

    def test_get_book_id(self):
        self.assertEqual(json.loads(app.book(1))["book"]["title"], "Emma")

    def test_get_genres(self):
        self.assertEqual(json.loads(app.book(1))["genres"], "Romance, Comedy, Fiction, Children's book")

    def test_get_subscriptions(self):
        self.assertEqual(json.loads(app.book(1))["subscriptions"], {'month': '14.58', 'year': '115.50'})

    def test_get_reviews(self):
        self.assertEqual(len(json.loads(app.book(1))["reviews"]), 2)

    def test_get_book_id_wrong(self):
        self.assertEqual(app.book(16), {'error': 'Book not found'})


class TestLeaveReviews(unittest.TestCase):
    def test_leave_reviews(self):
        with boddle(body="{\"book_id\": 1, \"rating\": 5, \"comment\": \"test\", \"user_id\": 1}"):
            self.assertEqual(app.review(), 'success')

    def test_get_reviews_wrong(self):
        self.assertEqual(app.review(), 'error')

class TestFilters(unittest.TestCase):
    def test_get_filters(self):
        self.assertEqual(json.loads(app.filters()), filters)


class Test_Invoice(unittest.TestCase):

    def setUp(self):
        self.token = jwt.encode({'id': 1, 'email': "test", 'verified': 1, 'admin': 1, "iat" : datetime.utcnow(), "exp" : datetime.utcnow() + timedelta(hours=2)}, secret, algorithm='HS256')
    def test_invoice(self):
        with boddle(body="{\"user_id\": 1, \"user_email\": \"test\", \"date\": \"2022-04-27\", \"total_price\": 1000, \"books\": [{\"id\": 6, \"subs_id\": 1, \"init_date\": \"2022-04-27\", \"exp_date\": 30}]}", headers={'Authorization': f'Bearer {self.token}'}):
            self.assertEqual(app.invoice(), 'success')

    def test_invoice_wrong(self):
        with boddle(headers={'Authorization': f'Bearer {self.token}'}):
            self.assertEqual(app.invoice(), 'error')


if __name__ == '__main__':
    unittest.main()	
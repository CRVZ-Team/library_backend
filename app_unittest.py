# import unittest
import app
from boddle import boddle

# ASK SANTIAGO



def test_app_index():
    assert app.index() == "Hello"




test_app_index()


# class TestApp(unittest.TestCase):
#     def test_app_login(self):
#         with boddle(params={'email': 'test', 'password': 'test'}):
#             self.assertEqual(target.login(), 'Login successful')

#         assert mywebapp.login() == token
    
#     with boddle(params={'email': 'test1', 'password': 'test'}):
#         assert mywebapp.login() == "Invalid email or password"

#     with boddle(params={'email': 'test', 'password': 'test1'}):
#         assert mywebapp.login() == "Invalid email or password"

# def test_app_signup():
#     with boddle(params={'email': 'test', 'password': 'test'}):
#         assert mywebapp.signup() == token
    

# def test_app_book():
#     with boddle(params={'token': token}):
#         assert mywebapp.book(1) == #book stuff

# def test_app_books():
#     assert mywebapp.books() == #book stuff

# def test_app_filters():
#     with boddle(params={'authors': 'F. Scott Fitzgerald', 'years': '1922'}):
#         assert mywebapp.filter_books() == #book stuff

#     with boddle(params={'genres': 'Comedy'}):
#         assert mywebapp.filter_books() == #book stuff


# def test_app_cart():
#     ##

# def test_app_invoice():
#     with boddle(params={'user_id': '1', 'date': '2019-01-01', 'total_price': '10.00', 'books': [1]}):
#         assert mywebapp.invoice() == #invoice stuff

# if __name__ == '__main__':
#     unittest.main()	
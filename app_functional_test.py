from webtest import TestApp
import unittest
import json
import app as app_module

class TestLogin(unittest.TestCase):
    def setUp(self):
        self.app = TestApp(app_module.app)

    def test_successfull_login(self):
        assert self.app.post('/api/login', params=json.dumps({'email': 'test', 'password': 'test'})).status_int == 200

    def test_wrong_password(self):
        assert self.app.post('/api/login', params=json.dumps({'email': 'test', 'password': 'test1'}), expect_errors=True).status_code == 401

    def test_wrong_email(self):
        assert self.app.post('/api/login', params=json.dumps({'email': 'test1', 'password': 'test'}), expect_errors=True).status_code == 401

    def test_exception_login(self):
        assert self.app.post('/api/login', params=json.dumps({'password': 'test'}), expect_errors=True).status_code == 500

class TestBooks(unittest.TestCase):
    def setUp(self):
        self.app = TestApp(app_module.app)

    def test_functional_books(self):
        assert self.app.get('/api/books').status_int == 200

    def test_functional_book(self):
        assert self.app.get('/api/book/1').status_int == 200
        
    def test_not_functional_book(self):    
        assert self.app.get('/api/book/20', expect_errors=True).status_code == 404

class TestFilters(unittest.TestCase):
    def setUp(self):
        self.app = TestApp(app_module.app)

    def test_functional_filters(self):
        assert self.app.get('/api/filters/authors').status_int == 200

    def test_functional_filter(self):
        assert self.app.post('/api/filter/books', params=json.dumps({'authors': ["F. Scott Fitzgerald"], 'years': [], 'genres': []})).status_int == 200
    
    def test_not_functional_filter(self):
        assert self.app.post('/api/filter/books', params=json.dumps({'years': [], 'genres': []}), expect_errors=True).status_code == 500

class TestReviews(unittest.TestCase):
    def setUp(self):
        self.app = TestApp(app_module.app)
    
    def test_functional_reviews(self):
        assert self.app.post('/api/comment', params=json.dumps({'book_id': '1', 'rating': '5', 'comment': 'Good book', 'user_id': '1'})).status_int == 201
    
    def test_not_functional_reviews(self):
        assert self.app.get('/api/comment', expect_errors=True).status_code == 405

if __name__ == '__main__':
    unittest.main()
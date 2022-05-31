import os
import jwt
from bottle import abort, request, response

from dotenv import load_dotenv
load_dotenv()

secret = os.environ.get('JWT_SECRET')

#Handle validation of JWT token
class AuthorizationError(Exception):
    """ A base class for exceptions used by bottle. """
    pass

def jwt_token_from_header():
    auth = request.headers.get('Authorization', None)
    print(auth)
    if not auth:
        raise AuthorizationError({'code': 'authorization_header_missing', 'description': 'Authorization header is expected'})
 
    parts = auth.split()
 
    if parts[0].lower() != 'bearer':
        raise AuthorizationError({'code': 'invalid_header', 'description': 'Authorization header must start with Bearer'})
    elif len(parts) == 1 or len(parts) > 2:
        raise AuthorizationError({'code': 'invalid_header', 'description': 'Authorization header must be Bearer token'})
    return parts[1]

#Decorator to check if the user is logged in
def requires_auth(f):
    def decorated(*args, **kwargs):
        try:
            token = jwt_token_from_header()
        except AuthorizationError:
            abort(401, 'Unauthorized')
 
        try:
            token_decoded = jwt.decode(token, secret, algorithms=['HS256']) 
        except Exception:
            abort(401, 'Invalid token')
        return f(*args, **kwargs)
 
    return decorated


# Handle CORS policy for the frontend
class EnableCors(object):
    name = 'enable_cors'
    api = 2

    def apply(self, fn, context):
        def _enable_cors(*args, **kwargs):
            # set CORS headers
            response.headers['Access-Control-Allow-Origin'] = os.environ.get('CORS_ORIGIN')
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Origin, Accept, Content-Type, X-Requested-With, X-CSRF-Token, Authorization'

            if request.method != 'OPTIONS':
                # actual request; reply with the actual response
                return fn(*args, **kwargs)

        return _enable_cors
    

#Handle CSRF token
# csrf_token = str_random(32)

# def csrf_protect():
#     if request.method == "POST":
#         token = session.pop('_csrf_token', None)
#         if not token or token != request.form.get('_csrf_token'):
#             response.status = 403
#             return response

# def generate_csrf_token():
#     if '_csrf_token' not in session:
#         session['_csrf_token'] = csrf_token
#     return session['_csrf_token']
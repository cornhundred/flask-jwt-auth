# project/server/models.py
# defining the user class

import datetime
import jwt

from project.server import app, db, bcrypt

# my own imports
from flask.views import MethodView
from flask import Blueprint, request, make_response, jsonify
import pdb
import ast

class User(db.Model):
  """ User Model for storing user related details """
  __tablename__ = 'users'

  id = db.Column(db.Integer, primary_key=True, autoincrement=True)
  email = db.Column(db.String(255), unique=True, nullable=False)
  password = db.Column(db.String(255), nullable=False)
  registered_on = db.Column(db.DateTime, nullable=False)
  admin = db.Column(db.Boolean, nullable=False, default=False)

  def __init__(self, email, password, admin=False):
    self.email = email
    self.password = bcrypt.generate_password_hash(
      password, app.config.get('BCRYPT_LOG_ROUNDS')
    ).decode()
    self.registered_on = datetime.datetime.now()
    self.admin = admin

  def encode_auth_token(self, user_id):
    """
    Generates the Auth Token
    :return: string
    """
    try:
      payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=5),
        'iat': datetime.datetime.utcnow(),
        'sub': user_id
      }
      return jwt.encode(
        payload,
        app.config.get('SECRET_KEY'),
        algorithm='HS256'
      )
    except Exception as e:
      return e

  @staticmethod
  def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """

    try:
      payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
      return payload['sub']
    except jwt.ExpiredSignatureError:
      return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
      return 'Invalid token. Please log in again'


class LoginAPI(MethodView):
    """
    User Login Resource
    """

    def post(self):
      # # get the post data
      # post_data = request.get_json()

      # get data from data (json not working??)
      # pdb.set_trace();
      post_data = ast.literal_eval(str(request.get_data())[2:-1])


      try:
        # fetch the user data
        user = User.query.filter_by(
          email=post_data.get('email')
        ).first()
        auth_token = user.encode_auth_token(user.id)
        if auth_token:
          responseObject = {
            'status': 'success',
            'message': 'Successfully logged in.',
            'auth_token': auth_token.decode()
          }
          return make_response(jsonify(responseObject)), 200

      except Exception as e:
        print(e)
        responseObject = {
          'status': 'fail',
          'message': 'Try again'
        }
        return make_response(jsonify(responseObject)), 500


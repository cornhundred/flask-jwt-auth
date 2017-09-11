# project/tests/test_user_model.py

import unittest
import json

from project.server import db
from project.server.models import User
from project.tests.base import BaseTestCase

class TestUserModel(BaseTestCase):

  def test_encode_auth_token(self):
    '''
    Test encode auth token
    '''
    inst_email = 'test@test.com'
    user = User(
        email = inst_email,
        password = 'test'
      )
    db.session.add(user)
    db.session.commit()
    auth_token = user.encode_auth_token(user.id)
    self.assertTrue(isinstance(auth_token, bytes))

  def test_decode_auth_token(self):
    '''
    Test Decode auth token
    '''
    user = User(
      email = 'test@test.com',
      password = 'test'
    )
    db.session.add(user)
    db.session.commit()
    auth_token = user.encode_auth_token(user.id)
    self.assertTrue(isinstance(auth_token, bytes))
    self.assertTrue(User.decode_auth_token(auth_token) == 1)

  def test_registrtion(self):
    """ Test for user registration """
    with self.client:
      response = self.client.post(
        'auth/register',
        data = json.dumps(dict(
          email = 'joe@gmail.com',
          password = '123456'
        )),
        content_type = 'application/json'
      )
      data = json.loads(response.data.decode())
      self.assertTrue(data['status'] == 'success')
      self.assertTrue(data['message'] == 'Successfully registered.')
      self.assertTrue(data['auth_token'])
      self.assertTrue(response.content_type == 'application/json')
      self.assertTrue(response.status_code, 201)

if __name__ == '__main__':
  unittest.main()
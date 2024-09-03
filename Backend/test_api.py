import unittest
from config import TestConfig
from main import create_app
from exts import db



class APITestCase(unittest.TestCase):
    app = create_app(TestConfig)
    client = app.test_client()


    def setUP(self):
        with self.app.app_context():
            db.init_app(self.app)

            db.create_all()

    # first test
    def test_hello_world(self):
        hello_response = self.client.get('/recipe/hello')
        json = hello_response.json
        print(json)
        self.assertEqual(json, {'message': 'Hello World'})

    def test_SignUp(self):
        signup_response = self.client.post('/auth/signup',
            json={
                "username": "test",
                "email": "testuser@gmail.com",
                "paasword": "password"
            }
        )

        status_code = signup_response.status_code
        self.assertEqual(status_code, 201)

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == '__main__':
    unittest.main()
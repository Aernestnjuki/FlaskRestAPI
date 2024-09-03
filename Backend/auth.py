from flask_restx import Resource, Namespace, fields
from models import User
from flask import request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, create_refresh_token
from flask import make_response

auth_ns = Namespace('auth', description="A namespace for our Authentication")

# models
signup_model = auth_ns.model(
    'Signup',
    {
        'username': fields.String(),
        'email': fields.String(),
        'paasword': fields.String()
    }
)

login_model = auth_ns.model(
    'Login',
    {
        "username": fields.String(),
        "paasword": fields.String()
    }
)


@auth_ns.route('/signup')
class SignUp(Resource):

    @auth_ns.expect(signup_model)
    def post(self):
        """Signup a user"""
        data = request.get_json()

        username = data.get('username')

        db_user = User.query.filter_by(username=username).first()

        if db_user is not None:
            return jsonify({"message": f"User with username {username} already exists!!"})

        new_user = User(
            username=data.get('username'),
            email=data.get('email'),
            paasword=generate_password_hash(data.get('paasword'))
        )

        new_user.save()

        return make_response(jsonify({"message": "User created successfully"}), 201)

@auth_ns.route('/login')
class Login(Resource):

    @auth_ns.expect(login_model)
    def post(self):
        """Login a user"""
        data = request.get_json()

        username = data.get('username')
        password = data.get('paasword')

        db_user = User.query.filter_by(username=username).first()

        if db_user and check_password_hash(db_user.paasword, password):
            access_token = create_access_token(identity=db_user.username)
            refresh_token = create_refresh_token(identity=db_user.username)

            return  jsonify(
                {
                    "access_token": access_token,
                    "refresh_toke": refresh_token
                 }
            )


from models import UserModel,db
from flask_restful import Resource, fields, marshal_with, reqparse
from flask_bcrypt import generate_password_hash
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from Resources.courses import resource_fields
from Resources.events import resource_fields

#user fields 
user_fields = {
    "id" : fields.Integer,
    "username" : fields.String,
    "email" : fields.String,
    "password" : fields.String,
    "role":fields.String,
    "courses": fields.Nested(resource_fields),
    "events": fields.Nested(resource_fields)
}

class User(Resource):
    #we are getting them with the "user_data = request.get_json()" in the app.py so now we dont need them but let them stay
    user_parser = reqparse.RequestParser()
    user_parser.add_argument('username', required=True, type=str, help="Enter the username")
    user_parser.add_argument('email', required=True, type=str,help="Enter the email")
    user_parser.add_argument('role', required=True, type=str,help="Enter the role")
    user_parser.add_argument('password', required=True, type = str, help="Enter the password")

    @marshal_with(user_fields)
    def post(self):
        data = User.user_parser.parse_args()
        data['password'] = generate_password_hash(data['password'])
        data['role'] = 'client'

        user = UserModel(**data)
        email = UserModel.query.filter_by(email=data['email']).one_or_none()

        if email:
            return {"message": "Email already taken", "status": "fail"}, 400

        try:
            user = UserModel(**data)
            db.session.add(user)
            db.session.commit()
            db.session.refresh(user)

            user_json = user.to_json()
            access_token = create_access_token(identity=user_json['id'])
            refresh_token = create_refresh_token(identity=user_json['id'])

            return {"message": "Account created successfully",
                    "status": "success",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": user_json }, 201
        except:
            return {"message": "Unable to create account", "status": "fail"}, 400   

class Login(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('email', required=True, help= 'email is required')
    parser.add_argument('password', required=True, help='password is required')

    def post(self):
        data = Login.parser.parse_args()
        user = UserModel.query.filter_by(email=data['email']).first()

        if user:
            is_password_correct = user.check_password(data['password'])
            if is_password_correct:
                user_json = user.to_json()
                access_token = create_access_token(identity=user_json['id'])
                refresh_token = create_refresh_token(identity=user_json['id'])
                return {"message": "Login successful",
                        "status": "success",
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "user": user_json,
                        }, 200
            else:
                return {"message": "invalid email/password", "status": "fail"}
        else:
            return {"message": "invalid email/password", "status": "fail"}
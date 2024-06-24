from flask import Flask,request,flash, jsonify, url_for
from flask_jwt_extended import JWTManager,jwt_required,get_jwt_identity,create_access_token,create_refresh_token
from models import db,EventModel,UserEventModel,UserModel
from flask_migrate import Migrate
from flask_restful import Api
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from datetime import timedelta
from itsdangerous import URLSafeSerializer
from sqlalchemy import or_
from Resources.courseEnrolment import UserCourses
from Resources.users import User,Login
from Resources.courses import Course
from Resources.profile import ProfileResource
from Resources.feedback import Feedback
from Resources.events import Events
from Resources.eventEnrolment import EnrolledEvents
from flask import Flask
from flask_mail import Mail, Message

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['BUNDLE_ERRORS'] = True
app.config["JWT_SECRET_KEY"] = "super-secret"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=30)

api = Api(app)
db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app)


api.add_resource(User, '/users', '/users/<int:id>')
api.add_resource(Login, '/login')
api.add_resource(UserCourses, '/userCourse','/userCourse/<int:id>')
api.add_resource(Course, '/course','/course/<int:id>')
api.add_resource(EnrolledEvents,'/enrolledEvent','/enrolledEvent/<int:id>')
api.add_resource(Feedback,'/feedback','/feedback/<int:id>')
api.add_resource(Events,'/event','/event/<int:id>')
api.add_resource(ProfileResource, '/profile','/profile/<int:id>')

def login():
    # Get user credentials from request data
    data = Login.user_parser.parse_args()
    email_or_username = data['usernameOrEmail']
    password = data['password']

    # Check if user exists by email or username
    user = UserModel.query.filter(or_(UserModel.email == email_or_username, UserModel.username == email_or_username)).first()

    if user:
        if user.verified:  # Check if user is verified
            if user.check_password(password):  # Validate password
                # Generate access token and refresh token
                user_json = user.to_json()
                access_token = create_access_token(identity=user_json['id'])
                refresh_token = create_refresh_token(identity=user_json['id'])
                return {
                    "message": "Login successful",
                    "status": "success",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": user_json
                }, 200
            else:
                return {"message": "Invalid email/username or password", "status": "fail"}, 403
        else:
            return {"message": "Email not verified. Please verify your email first.", "status": "fail"}, 403
    else:
        return {"message": "Invalid email/username or password", "status": "fail"}, 404

if __name__ == "__main__":
    app.run(debug=True, port=5000)
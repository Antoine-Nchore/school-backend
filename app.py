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
from flask import Flask
from flask_mail import Mail, Message

app = Flask(__name__)
mail = Mail(app)
api = Api(app)
CORS(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['BUNDLE_ERRORS'] = True

app.config["JWT_SECRET_KEY"] = "thisisasecrettoeveryone"  # we should remember to change this
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=30)

@app.route("/")
def hello():
    return "Hello world"

if __name__ == "__main__":
    app.run(debug=True, port=5000)
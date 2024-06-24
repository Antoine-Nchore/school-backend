from flask_restful import Resource , marshal
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import UserModel, db 
from Resources.users import user_fields 
from Resources.auth import admin_required

class AdminUserResource(Resource):
    @jwt_required()
    @admin_required
    def get(self):
        users = UserModel.query.all()
        return marshal(users, user_fields)
from flask_restful import Resource, fields, marshal_with, reqparse
from models import ProfileModel,UserModel,db
# will help us get the identity of the logged in user
from flask_jwt_extended import jwt_required, get_jwt_identity

profile_fields = {
    "first_name": fields.String,
    "last_name": fields.String,
    "phone": fields.String,
    "email": fields.String,
}
#class profile 
class ProfileResource(Resource):
    profile_parser = reqparse.RequestParser()
    profile_parser.add_argument('first_name', type=str, help="Enter the first name")
    profile_parser.add_argument('last_name', type=str, help="Enter the last name")
    profile_parser.add_argument('phone', type=str, help="Enter the phone number")
    profile_parser.add_argument('email', type=str, help="Enter the email")

    #getting identity of the logged in user jwt required
    @marshal_with(profile_fields)
    @jwt_required()
    #once in front end remove the user_id from the bracket
    def get(self):
        # Fetch the profile for a specific user

        #getting the user_id when a user logs in --- will do this in front-end
        current_user_id = get_jwt_identity()
        print(current_user_id)
        #use this on front end
        profile = ProfileModel.query.filter_by(user_id=current_user_id).first()

        if not profile:
            return {"message": "Profile not found", "status": "fail"}, 404

        return profile

    @jwt_required()
    def post(self):
        data = ProfileResource.profile_parser.parse_args()

        # Check if the user exists
        current_user_id = get_jwt_identity()
        
        # Fetch the profile for the user
        profile = ProfileModel.query.filter_by(user_id=current_user_id).first()

        if not profile:
            # If the profile does not exist, create a new one
            profile = ProfileModel(user_id=current_user_id)

        # Update the profile
        profile.first_name = data['first_name']
        profile.last_name = data['last_name']
        profile.phone = data['phone']
        profile.email = data['email']

        try:
            db.session.add(profile)
            db.session.commit()
            return {"message": "Profile updated successfully", "status": "success"}, 200
        except: 
            return {"message": "Unable to update profile", "status": "fail"}, 500
        
    @jwt_required
    def delete(self):
        # Check if the user exists
        current_user_id = get_jwt_identity()

        user = UserModel.query.get(current_user_id)
        if not user:
            return {"message": "User not found", "status": "fail"}, 404

        # Fetch the profile for the user
        profile = ProfileModel.query.filter_by(user_id=current_user_id).first()

        if not profile:
            return {"message": "Profile not found", "status": "fail"}, 404

        try:
            db.session.delete(profile)
            db.session.commit()
            return {"message": "Profile deleted successfully", "status": "success"}, 200
        except:
            return {"message": "Unable to delete profile", "status": "fail"}, 500

from models import db, UserEventModel, EventModel , UserModel
from flask_jwt_extended import jwt_required,get_jwt_identity
from flask_restful import Resource,fields,  reqparse,marshal

resource_fields = {
    "id": fields.Integer,
    "user_id":fields.Integer,
    "event_id": fields.Integer,
}

class EnrolledEvents(Resource):
    enrolledEvent_parser = reqparse.RequestParser()
    enrolledEvent_parser.add_argument('event_id', required = True,type=int,help="event id is required" )

    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        if current_user_id:
            UserEvent = UserEventModel.query.filter_by(user_id=current_user_id).all()
            return marshal(UserEvent, resource_fields)
        else:
            return {"message":"you have not enrolled for any event"}
        
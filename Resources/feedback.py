from flask_restful import Resource ,fields ,marshal_with,reqparse ,marshal
from flask_jwt_extended import jwt_required , get_jwt_identity
from models import FeedbackModel ,db,UserModel

Feedback_fields = {
    'id': fields.Integer,
    'user_id': fields.Integer,
    'username': fields.String,
    'comment': fields.String,
    'likes': fields.Integer,
    'dislikes': fields.Integer,
    'created_at': fields.DateTime,
    'updated_at': fields.DateTime,
}

class Feedback(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('comment', required=False)
    parser.add_argument('likes', required= False )
    parser.add_argument('dislikes', required= False)
    
#Read feedbacks
    @marshal_with(Feedback_fields)
    def get(self, id=None):
    
        if id:
            feedback = FeedbackModel.query.filter_by(id = id).first()
            return feedback
        else:
            feedbacks = FeedbackModel.query.all()

            return feedbacks
        

    @jwt_required()
    def post(self):
      data = Feedback.parser.parse_args() 
      current_user_id = get_jwt_identity()
      data['user_id'] = current_user_id
      user = UserModel.query.filter_by(id = current_user_id).first()
      data['username'] = user.username
      feedback= FeedbackModel(**data)

      try:
          db.session.add(feedback)
          db.session.commit()
          return {'message':'successfully added your feedback'},201
      except Exception as e:
                print(f"An error occurred: {e}")
                return {"message":"User already has a feedback with this user_id"},400

      
 
    
    @jwt_required()
    def patch(self,id):
        data = Feedback.parser.parse_args()
        Feedbacks = FeedbackModel.query.get(id)

        if Feedback_fields:
            for key,value in data.items():
                setattr(Feedbacks,key,value)
            try:
                db.session.commit()

                return {"message":"Feedback updated successfully"}
            except:
                return {"message":"Feedback unable to be updated"}
            
        else:
            return {"message":"Feedback not found"}
        

    @jwt_required()
    def delete(self,id):
        Feedback = FeedbackModel.query.filter_by(id = id).first()
        if Feedback:
            try:
                db.session.delete(Feedback)
                db.session.commit()

                return {"message":"Feedback deleted"}
            except:
                return {"message":"Feedback unable to be deleted"}
        else:
            return {"message":"Feedback not found"}


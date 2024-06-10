from models import db , UserCourseModel , CourseModel
from flask_jwt_extended import jwt_required,get_jwt_identity
from flask_restful import Resource,fields, marshal_with, reqparse,marshal


userCourse_fields = {
    "id": fields.Integer,
    "user_id":fields.Integer,
    "course_id": fields.Integer,
}
 
class UserCourses(Resource):
    userCourse_parser = reqparse.RequestParser()
    userCourse_parser.add_argument('course_id', required = True,type=int,help="course id is required" )
    
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        if current_user_id:
            UserCourse = UserCourseModel.query.filter_by(user_id=current_user_id).all()
            return marshal(UserCourse, userCourse_fields)
        else:
            return {"message":"you have not registered for any Course"}
        
    #  I added some things to this post method to deal with the relationships between user 
        # and courses 
    #it will be posted to the profile page once a user books it
    @jwt_required()
    def post(self):
      data = UserCourses.userCourse_parser.parse_args()
      current_user_id = get_jwt_identity()
      check_course_existence = CourseModel.query.get(data['course_id'])

      if not check_course_existence:
            return {"message": "Course not found"}, 404
          
      existing_booking = UserCourseModel.query.filter_by(user_id=current_user_id, course_id=data['course_id']).first()

      if existing_booking:
            # User has already booked for this course
            return {"message": "You have already booked for this Course"}, 400

      data['user_id'] = current_user_id
      new_course = UserCourseModel(**data)

      db.session.add(new_course)
      db.session.commit()
      
      return {"message": "Course booked successfully"}, 201
 
    @marshal_with(userCourse_fields)
    @jwt_required()
    def patch(self,id):
        data = UserCourses.userCourse_parser.parse_args()
        userCourse = UserCourseModel.query.get(id)

        if userCourse:
            for key,value in data.items():
                setattr(userCourse,key,value)
            try:
                db.session.commit()

                return {"message":"userCourse updated successfully"}
            except:
                return {"message":"userCourse unable to be updated"}
            
        else:
            return {"message":"userCourse not found"}
        

    @jwt_required()
    def delete(self,id):
        userCourse = UserCourseModel.query.filter_by(id = id).first()
        if userCourse:
            try:
                db.session.delete(userCourse)
                db.session.commit()

                return {"message":"userCourse deleted"}
            except:
                return {"message":"userCourse unable to be deleted"}
        else:
            return {"message":"userCourse not found"}


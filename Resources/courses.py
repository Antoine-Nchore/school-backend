from flask_restful import Resource, reqparse, fields, marshal_with
from flask_jwt_extended import  jwt_required
from Resources.auth import admin_required
from models import db, CourseModel

resource_fields = {
    'id': fields.Integer,
    'title': fields.String,
    'category': fields.String,
    'price': fields.Integer,
    'image': fields.String,
    'description': fields.String,
    'duration': fields.String,
    'created_at': fields.DateTime,
    'updated_at': fields.DateTime,
}

class Course(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('title', required=True, help="Title is required!")
    parser.add_argument('category', required=True, help="Category is required!")
    parser.add_argument('price', required=True, help="Price is required!")
    parser.add_argument('image', required=True, help="Image is required!")
    parser.add_argument('pdf_file', required=False, help="You might be required to add a pdf_file!")
    parser.add_argument('description', required=True, help="Description is required!")
    parser.add_argument('duration', required=True, help="Duration is required!")

    @marshal_with(resource_fields)
    def get(self, id=None):
        if id:
            course = CourseModel.query.filter_by(id=id).first()
            return course
        else:
            courses = CourseModel.query.all()
            return courses
    
    @jwt_required()
    @admin_required    
    def post(self):
        data = Course.parser.parse_args()
        course = CourseModel(**data)

        try:
            db.session.add(course)
            db.session.commit()
            
            return{"message": "Course added successfully", "status": "success"}
        except Exception as e:
            return {"message": "Unable to add course", "status": "fail"}
        
    @jwt_required()
    @admin_required 
    def delete(self, id):
        try:
            course = CourseModel.query.filter_by(id=id).first()

            if course:
                db.session.delete(course)
                db.session.commit()
                return{"message": "Course deleted successfully", "status": "success"}
            else:
                return {"message": "Course not found", "status": "fail"}
        except:
            return {"message": "Unable to delete course", "status": "success"}
        
    @jwt_required()
    @admin_required 
    def patch(self, id):
        if id:
            course = CourseModel.query.filter_by(id=id).first()

            if course:
                data = Course.parser.parse_args()

                for key, value in data.items():
                    if value is not None:
                        setattr(course, key, value)

                try:
                    db.session.commit()
                    return {"message": "Course updated successfully", "status": "success" }
                except Exception as e:
                    print(f"An error occurred: {e}")
                    db.session.rollback()
                    return {"message": "Unable to update course", "status": "fail"}
            else:
                return {"message": "Course not found", "status": "fail"}

        


   

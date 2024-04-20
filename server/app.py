#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from werkzeug.security import check_password_hash

from config import app, db, api
from models import User

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):
    
    def post(self):
        json = request.get_json()
        user = User(
            username=json['username']
        )
        user.password_hash = json['password']
        db.session.add(user)
        db.session.commit()
        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        User_id = session.get('user_id')
        if User_id:
            User = User.query.get(User_id)
            if User:
                return User.to_dict()

        return {}, 204

class Login(Resource):
    def post(self):
        json_data = request.get_json()
        username = json_data.get('username')
        password = json_data.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            return user.to_dict()
        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        session['user_id'] = None
        return {}, 204
    
def hash_password(password):
    # Use a secure password hashing library like bcrypt
    # Example using bcrypt:
    # hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    # return hashed_password
    return password  # Dummy hashing for demonstration

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)

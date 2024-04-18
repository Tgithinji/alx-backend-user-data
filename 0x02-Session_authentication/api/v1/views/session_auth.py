#!/usr/bin/env python3
"""session_auth routes"""
from flask import jsonify, request
from api.v1.views import app_views
from models.user import User
import os


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def session_auth():
    """handle user login"""
    email = request.form.get('email')
    password = request.form.get('password')

    if email is None or email == '':
        return jsonify({'error': 'email missing'}), 400
    if password is None or password == '':
        return jsonify({'error': 'password missing'}), 400

    users = User.search({'email': email})
    if not users or len(users) == 0:
        return jsonify({'error': 'no user found for this email'}), 404
    for u in users:
        if u.is_valid_password(password):
            from api.v1.app import auth
            session_id = auth.create_session(u.id)
            user_dict = jsonify(u.to_json())
            session_name = os.getenv('SESSION_NAME')
            user_dict.set_cookie(session_name, session_id)
            return user_dict
    return jsonify({'error': 'wrong password'}), 401

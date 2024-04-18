#!/usr/bin/env python3
""" auth module """
import os
from flask import request
from typing import List, TypeVar


class Auth:
    """ Manage the API authentication
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """require auth """
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        paths = []
        path = path.rstrip('/')
        for i in excluded_paths:
            i = i.rstrip('/')
            paths.append(i)
        if path in paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """ authorization header """
        if request is None or 'Authorization' not in request.headers:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """ Current_user"""
        print(request)
        return None

    def session_cookie(self, request=None):
        """returns a cookie value from a request
        """
        if request is None:
            return None
        session_name = os.getenv('SESSION_NAME')
        return request.cookies.get(session_name)

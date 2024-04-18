#!/usr/bin/env python3
"""session_auth module"""
import uuid
from api.v1.auth.auth import Auth
from models.user import User


class SessionAuth(Auth):
    """Session Auth"""
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Create session"""
        if user_id is None or not isinstance(user_id, str):
            return None
        session_id = uuid.uuid4()
        self.user_id_by_session_id[str(session_id)] = user_id
        return str(session_id)

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Retrieving User id for session id"""
        if session_id is None or not isinstance(session_id, str):
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """Get current user"""
        cookie = self.session_cookie(request)
        session_id = self.user_id_for_session_id(cookie)
        return User.get(session_id)
    
    def destroy_session(self, request=None):
        """destroy session"""
        if request is None:
            return False
        cookie = self.session_cookie(request)
        if cookie is None:
            return False
        session_id = self.user_id_for_session_id(cookie)
        if session_id is None:
            return False
        del self.user_id_by_session_id[cookie]
        return True

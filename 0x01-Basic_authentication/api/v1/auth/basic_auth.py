#!/usr/bin/env python3
""" basic_auth module"""
import base64
import binascii
from api.v1.auth.auth import Auth
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    """Basic Auth"""
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """extract base64 authorization header"""
        if authorization_header is None or not isinstance(authorization_header,
                                                          str):
            return None
        if not authorization_header.startswith('Basic '):
            return None
        basic, user = authorization_header.split()
        return user

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> str:
        """returns the decoded value of a Base64 string
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            base64_str = base64.b64decode(base64_authorization_header)
        except (TypeError, binascii.Error):
            return None
        return base64_str.decode('utf-8')

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str
                                 ) -> (str, str):
        """returns the user email and password from the Base64 decoded value.
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        return decoded_base64_authorization_header.split(':')

    def user_object_from_credentials(self,
                                     user_email: str, user_pwd: str
                                     ) -> TypeVar('User'):
        """returns the User instance based on his email and password.
        """
        users = User.search({'email': user_email})
        if not users or len(users) == 0:
            return None
        for u in users:
            if u.is_valid_password(user_pwd):
                return u

        return None

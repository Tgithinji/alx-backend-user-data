#!/usr/bin/env python3
""" basic_auth module"""
import base64
import binascii
from api.v1.auth.auth import Auth


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

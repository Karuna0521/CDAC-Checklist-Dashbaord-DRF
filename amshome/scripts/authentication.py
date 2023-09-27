import json

import jwt
from django.conf import settings
from rest_framework import exceptions
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError, AuthenticationFailed
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.backends import TokenBackend
from amshome.mixin import data_encrypt
from amshome.models import User
from ams.settings import VERIFYING_KEY

class MyJWTAuthentication(JWTAuthentication):
    
    def get_validated_token(self, raw_token):
        token=raw_token.decode("utf-8")
        print(token)
        options = {
            'verify_exp': True,
            'verify_aud': False
        }
        try:
            valid_data = jwt.decode(token, VERIFYING_KEY, algorithm='RS256',options=options,verify=True)
            print(valid_data)
            return token
        except Exception as e:
            print(e)

    def authenticate(self, request):

        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        print("decoded header :- ",self.get_header(request).decode())

        options = {
            'verify_exp': False,
            'verify_aud': False
        }
        try:
            key= VERIFYING_KEY
            key= "-----BEGIN PUBLIC KEY-----\n" + request.headers["X-Public-Key"] + "\n-----END PUBLIC KEY-----"

            print("public key : ",key)
            valid_data = jwt.decode(validated_token, key=key, algorithm='RS256',options=options)

            user = valid_data['email']

            try:
                print(user)
                decode_user = data_encrypt(email=user)
                user = User.objects.get(email =decode_user["email"])
                print("user", user)
            except User.DoesNotExist:
                raise AuthenticationFailed(('User not found'),code='user_not_found')

            if not user.is_active:
                raise AuthenticationFailed(('User is inactive'),code='user_inactive')
            user.is_authenticated = True
            return (user, None)

        except Exception as e:
            print("exception", e)

class InvalidToken(Exception):
    pass
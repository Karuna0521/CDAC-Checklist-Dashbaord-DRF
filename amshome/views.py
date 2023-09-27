from collections import OrderedDict
import datetime
import json
import random
import string
from rest_framework import generics
from rest_framework.permissions import *

from .scripts.permissions import *

from .scripts.authentication import MyJWTAuthentication

from .models import *
from .serializers import *
# import serializers as serializers
from rest_framework import status
from rest_framework.response import Response
from rest_framework import serializers
from django.contrib.auth.hashers import make_password 
from .mixin import *
from rest_framework.views import *
from django.contrib.auth import authenticate, login
# from rest_framework_jwt.settings import api_settings
# from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
import jwt


# Create your views here.
"""User Registration"""

class RegisterView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = UserSerializer

    def captchaUpdate(captcha):
        c_data = Captcha_count_ser(captcha,data={"count":captcha.count+1})
        c_data.is_valid(raise_exception=True)
        c_data.save()

    def create(self, request, *args, **kwargs):
        # data = request.data
        data = OrderedDict()
        data.update(request.data)
        try:
            key = request.data["key"]
            ip = ''.join([char for char in key if not char.isalpha()])
            try:
                captcha = Captcha.objects.get(key=key)
            except Captcha.DoesNotExist:
                raise serializers.ValidationError("captcha not valid")
            if ip != request.META["REMOTE_ADDR"] and captcha.key != key:
                self.captchaUpdate(captcha)
                raise serializers.ValidationError("captcha not valid")
            if captcha.captcha_str != str(data["captcha_str"]):
                if captcha.count == 3 : 
                    captcha.delete()
                    raise serializers.ValidationError("captcha was expired")
                self.captchaUpdate(captcha)
                raise serializers.ValidationError("captcha not valid")
        except Captcha.DoesNotExist:
            raise serializers.serializers.ValidationError("captcha not valid")


        if data["password"] != data["confirm_password"]:
            raise serializers.ValidationError({"password": "Passwords won't match!"})
        password = data["password"]
        username = data["email"]
        serializer = UserSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        encode_data = data_encrypt(first_name=data["first_name"],last_name=data["last_name"],email=data["email"],mobile_no=data["mobile_no"])

        data = encode_data
        data['date_joined'] = datetime.datetime.now()
        data['time'] = datetime.datetime.now()
        data['is_active'] = 1
        data["username"] = data["email"]
        data["password"] = make_password(password)

        saveUserSer = saveEncryptedDataOfUserSerializer(data=data)
        saveUserSer.is_valid(raise_exception=True)
        user = saveUserSer.save()
        captcha.delete()
        user_role = AuthGroup.objects.get(name="public authority")
        data = {"user": user.pk, "group": user_role.pk}
        u_g = UserGroupsSerializer(data=data)
        if u_g.is_valid(raise_exception=True):
            u_g.save()
        
        return Response({"status": 1, "errors": [], "status_code": status.HTTP_201_CREATED})



class Captcha_API(APIView):
    def generate_random_string(self):
        letters = string.ascii_letters
        random_string = ''.join(random.choice(letters) for _ in range(5))
        return random_string

    def post(self, request):
        Captcha_string = self.generate_random_string()
        print(Captcha_string)
        key = self.generate_random_string(
        ) + str(request.META["REMOTE_ADDR"]) + self.generate_random_string()
        captcha = CaptchaSerializer(
            data={"captcha_str": Captcha_string, "key": key,"count":0})
        captcha.is_valid(raise_exception=True)
        c = captcha.save()
        return Response({
                        "status": 1,
                        "errors": [],
                        "status_code": 200,
                        "data": {"c_id": c.pk, "captcha_str": Captcha_string, "key": key}
                        }, status=status.HTTP_200_OK)



class UserData(APIView):

    
    def post(self, request, *args, **kwargs):
        user_id = request.data["id"]
        try : 
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'status': 0, 'errors': 'DoesNotExist', 'message': "User not exist", "status-code": status.HTTP_404_NOT_FOUND}, status=status.HTTP_404_NOT_FOUND)
        user_ser = userDataFetchSerializer(user)
        decoded_data = data_decrypt(username=user_ser.data["username"],first_name=user_ser.data["first_name"],last_name=user_ser.data["last_name"],mobile_no=user_ser.data["mobile_no"],email=user_ser.data["email"])
        return Response({'status': 1, 'errors': '', 'data': decoded_data, "status-code": status.HTTP_200_OK}, status=status.HTTP_200_OK)


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        try : 
            UserGroup = UserGroups.objects.get(user=user.pk)
        except UserGroups.DoesNotExist:
            pass
        token['role'] = UserGroup.group.name
        decrypt_data = data_decrypt(username=user.username,email=user.email)
        token["username"] = decrypt_data["username"]
        token["email"] = decrypt_data["email"]
        token["user_id"] = user.pk
        return token
    
from django.utils import timezone
class AMSlogin(APIView):
    def captchaUpdate(self,captcha):
        c_data = Captcha_count_ser(captcha,data={"count":captcha.count+1})
        c_data.is_valid(raise_exception=True)
        c_data.save()

    def post(self, request, *args, **kwargs):
        data = OrderedDict()
        data.update(request.data)
        try:
            key = request.data["key"]
            ip = ''.join([char for char in key if not char.isalpha()])
            try:
                captcha = Captcha.objects.get(key=key)
            except Captcha.DoesNotExist:
                raise serializers.ValidationError("captcha not valid")
            if ip != request.META["REMOTE_ADDR"] and captcha.key != key:
                self.captchaUpdate(captcha)
                raise serializers.ValidationError("captcha not valid")
            if captcha.captcha_str != str(data["captcha_str"]):
                if captcha.count == 3 : 
                    captcha.delete()
                    raise serializers.ValidationError("captcha was expired")
                self.captchaUpdate(captcha)
                raise serializers.ValidationError("captcha not valid")
        except Captcha.DoesNotExist:
            raise serializers.serializers.ValidationError("captcha not valid")



        encrypt_username = data_encrypt(username=request.data["username"])
        password = request.data.get('password')
        user = authenticate(username=encrypt_username["username"], password=password)
        if user is not None:
            login(request, user)
            user_data = User.objects.filter(username=user)
        
            decrypt_data = data_decrypt(username=user_data[0].username,email=user_data[0].email)
            refresh = MyTokenObtainPairSerializer.get_token(user_data[0])
            access = str(refresh.access_token)
            data={}
            data["refresh_token"] = str(refresh)
            data["access_token"] = str(access)
            user_data.update(last_login=datetime.datetime.utcnow())
            captcha.delete()
            return Response({'status': 1, 'errors': '', 'data':data ,"status-code": status.HTTP_200_OK}, status=status.HTTP_200_OK)
        else:
            
            return Response({'status': 0, 'errors': '', 'message': "Invalid User Credentials ", "status-code": status.HTTP_401_UNAUTHORIZED},status=status.HTTP_401_UNAUTHORIZED)
    

class dummyapi(APIView):
    authentication_classes=[MyJWTAuthentication]
    permission_classes=[IsAuthenticated,IsPublicAuthority]
    def get(self, request, *args, **kwargs):

        return Response("done")
    

def validateUserGroup(uid, user_group_id):
        try : # fetch if db has user matching uid
            u_g = UserGroups.objects.get(user_id=uid) # select * from UserGroups where user_id = uid)
        except UserGroups.DoesNotExist: # no user so return false
            return False
        if u_g.group_id == user_group_id: 
           return True
        return False


class PaAudRevMap_API(APIView):
    # authentication_classes=[MyJWTAuthentication]
    # permission_classes=[IsAuthenticated,IsAdmin]
    def get(self, request, *args, **kwargs):
        user_mapping = PaAudRevMap.objects.all()
        ser = PaAudRevMapSerializer(user_mapping, many=True)
        return Response({'data':ser.data, 'status-code': status.HTTP_200_OK}, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        req_mapping = request.data
        print('--->',req_mapping)
        try:
            req_pa_id = req_mapping['pa_id']
            req_rev_id = req_mapping['rev_id']
            req_aud_id = req_mapping['aud_id']
            if validateUserGroup(req_pa_id, 4) is not True:
                error = str(req_pa_id) + " is not Public Authority"
                return Response({'status': 0, 'errors': error, 'data':'' ,"status-code": status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
            if validateUserGroup(req_rev_id, 3) is not True:
                error = str(req_rev_id) + " is not Reviewer"
                return Response({'status': 0, 'errors': error, 'data':'' ,"status-code": status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
            if validateUserGroup(req_aud_id, 2) is not True:
                error = str(req_aud_id) + " is not Auditor"
                return Response({'status': 0, 'errors': error, 'data':'' ,"status-code": status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
            try:
                # to get object with refrence to existing pa_id in paaudrev table
                existing_mapping = PaAudRevMap.objects.get(pa_id=req_pa_id)
                ser = PaAudRevMapSerializer(existing_mapping)
                return Response({'status': 1, 'errors': '', 'data':ser.data ,"status-code": status.HTTP_200_OK}, status=status.HTTP_200_OK)
            except:
                # if pa_id doest not exists in table, create new
                PaAudRevMap.objects.create(
                    pa_id = req_pa_id,
                    rev_id = req_rev_id,
                    aud_id = req_aud_id,
                )
                return Response({'status': 1, 'errors': '', 'data':req_mapping ,"status-code": status.HTTP_200_OK}, status=status.HTTP_200_OK)
        except:
            return Response({'status': 0, 'errors': 'pa_id, rev_id and aud_id are required feilds.', 'data':'' ,"status-code": status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
        
    def patch(self, request, *args, **kwargs):
        try:
            req_mapping = request.data
            req_pa_id = req_mapping['pa_id']
            req_rev_id = req_mapping['rev_id', []]
            req_aud_id = req_mapping['aud_id', []]
            if validateUserGroup(req_pa_id, 4) is not True:
                error = str(req_pa_id) + " is not Public Authority"
                return Response({'status': 0, 'errors': error, 'data':'' ,"status-code": status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
            if validateUserGroup(req_rev_id, 3) is not True:
                error = str(req_rev_id) + " is not Reviewer"
                return Response({'status': 0, 'errors': error, 'data':'' ,"status-code": status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
            if validateUserGroup(req_aud_id, 2) is not True:
                error = str(req_aud_id) + " is not Auditor"
                return Response({'status': 0, 'errors': error, 'data':'' ,"status-code": status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
            try:
                mapping = PaAudRevMap.objects.get(pa_id=req_pa_id)
                print("this is id",mapping)
                ser = PaAudRevMapSerializer(mapping, data = req_mapping, partial=True)
                if ser.is_valid():
                    ser.save()
                    return Response({'status': 1, 'errors': '', 'data': ser.data, 'status-code': status.HTTP_200_OK}, status=status.HTTP_200_OK)
                return Response({'status':0, 'message':'Something went wrong','errors':ser.errors, 'status-code': status.HTTP_406_NOT_ACCEPTABLE}, status=status.HTTP_406_NOT_ACCEPTABLE)
            except Exception as e:
                error = "Mapping with pa_id " + str(req_pa_id) + " does not exists!"
                return Response({'status':0, 'errors': error, 'message':'', 'status-code':status.HTTP_404_NOT_FOUND }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print('--->',e)
            return Response({'status':0, 'message':'', 'errors': 'pa_id, rev_id and aud_id are required feilds.', 'data':'','status-code': status.HTTP_403_FORBIDDEN}, status=status.HTTP_403_FORBIDDEN)


   
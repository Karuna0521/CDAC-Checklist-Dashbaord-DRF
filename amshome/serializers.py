import re
from django.contrib.auth.models import User
from .models import *
from rest_framework.validators import UniqueValidator
from django.utils.translation import gettext as _
from django.core.validators import *
from rest_framework import serializers, request
from rest_framework import serializers


mobile_number = RegexValidator(r'^\d{10}$', 'Please enter valid mobile number.')
alpha = RegexValidator(r'^[A-Za-z\s]+$', 'Only alphabatic characters are allowed')
emailregex = RegexValidator(r'[^@]+@[^@]+\.[^@]+','Please Enter Valid Email')
mailregex = RegexValidator(r'[^@]+@[^@]+\.[^@]+')
alphanumeric = RegexValidator(r'^[A-Za-z\s\d,\/\"\'{}:_-]+$', 'Only alphanumeric characters are allowed')
form_name = RegexValidator(r'^[A-Za-z\s\d-]+$', 'Only hyphen and alphanumeric characters are allowed')
description = RegexValidator(r'^[A-Za-z\s\d.-?,:]{1,500}$', 'Please provide valid details')






class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        # validators=[UniqueValidator(queryset=User.objects.all()), MaxLengthValidator(2)],
        validators=[UniqueValidator(queryset=User.objects.all())],
    )
    mobile_no = serializers.IntegerField(
        required=True,
        validators=[mobile_number,UniqueValidator(queryset=User.objects.all())],
    )
    #first_name =serializers.SerializerMethodField('get_name')emailregex

    password = serializers.CharField(
        required=True,
    )

    def validate_password(self,password):

        if len(password) < 8:
            raise serializers.ValidationError('Make strong password')
    
        if not any(char.isupper() for char in password):
            raise serializers.ValidationError('Make strong password')
    
        if not any(char.islower() for char in password):
            raise serializers.ValidationError('Make strong password')
    
        if not any(char.isdigit() for char in password):
            raise serializers.ValidationError('Make strong password')
    
        special_characters = re.compile(r'[@_!#$%^&*()<>?/\|}{~:]')
        if not special_characters.search(password):
            raise serializers.ValidationError('Make strong password')  
    
        return password

    class Meta:
        model = User
        fields = ['password', 'email','first_name','last_name', 'mobile_no']
        extra_kwargs = {
            'email': {'required': True},
            'mobile_no': {'required': True},
        }

class userDataFetchSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["username","first_name","last_name","mobile_no","email"]


class saveEncryptedDataOfUserSerializer(serializers.ModelSerializer):
    email = serializers.CharField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all(),message="EmailId already exist")],
    )
    mobile_no = serializers.CharField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all(),message="MobileNo Already Exist")],
    )


    class Meta:
            model = User
            fields = ['password', 'email','username' ,'first_name','last_name', 'mobile_no','date_joined','is_active']
            extra_kwargs = {
                'email': {'required': True},
                'mobile_no': {'required': True},
            }




class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    
class UserGroupsSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserGroups
        fields = '__all__'


class CaptchaSerializer(serializers.ModelSerializer):

    class Meta:
        model = Captcha
        fields = '__all__'

class Captcha_count_ser(serializers.ModelSerializer):

    class Meta:
        model = Captcha
        fields = ["count"]


class PaAudRevMapSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaAudRevMap
        fields = '__all__'
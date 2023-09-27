from django.contrib import admin
from django.urls import path
# from django.conf.urls import url, include
from .views import *


urlpatterns = [
      path('register',RegisterView.as_view()),
      path('generateCaptcha',Captcha_API.as_view()),
      path('mapPaRevAud',PaAudRevMap_API.as_view()),
      path('userData',UserData.as_view()),
      path('login/', AMSlogin.as_view(), name='user-login'),
      path('dummyapi/',dummyapi.as_view())
]
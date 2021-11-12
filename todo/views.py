from django.shortcuts import render

from django.contrib.auth.models import User
from django.contrib.auth import login, logout
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password

from django.dispatch import receiver
from django.urls import reverse
from django_rest_passwordreset.signals import reset_password_token_created
from django.core.mail import send_mail 

from .serializers import userSerializers, LoginSerializer, RegistrationSerializer, ChangePasswordSerializer
from rest_framework.generics import GenericAPIView

from django.core.exceptions import ValidationError

from django.contrib.auth.tokens import PasswordResetTokenGenerator

from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication

from django_rest_passwordreset.models import ResetPasswordToken


# Create your views here.

@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, *args, **kwargs):

	email_plaintext_message = "{}?token={}".format(reverse('password_reset:reset-password-request'), reset_password_token.key)

	send_mail(
		# title:
		"Password Reset for {title}".format(title="Some website title"),
		# message:
		email_plaintext_message,
		# from:
		"noreply@somehost.local",
		# to:
		[reset_password_token.user.email]
	)
	print(email_plaintext_message)

class userAPIView(APIView):

	def get(self,request):
		users= User.objects.all()
		s1 = userSerializers(users,many=True)
		return Response(s1.data)

class LoginView(APIView):

	def post(self,request):
		s1 = LoginSerializer(data=request.data)
		s1.is_valid(raise_exception=True)
		user = s1.validated_data["user"]
		login(request,user)
		token, created = Token.objects.get_or_create(user=user)
		request.session['user_token']=token.key
		print(request.session['user_token'])
		return Response({"token":token.key,"msg":"login Successfully"},status=200)

class LogoutView(APIView):
	# permission_classes = (IsAuthenticated,)
	authentication_classes = [TokenAuthentication]

	def post(self, request):
		print(request.META.get('HTTP_AUTHORIZATION'))
		print(request.user)
		if (request.META.get('HTTP_AUTHORIZATION'))==(request.session['user_token']):
			logout(request)
			return Response({"message":"Logout Successfully"},status=204)
		else:
			return Response({"msg":"enable to delete"})

class RegistrationView(APIView):

	def post(self,request):
		username = self.request.data['username']
		email =  self.request.data['email']
		password = self.request.data['password']
		print(username)
		data={
			"username":username,
			"email":email,
			"password":make_password(password)
		}
		print(data['password'])
		s1 = RegistrationSerializer(data=data)
		print("*"*100)
		if s1.is_valid():
			print("*"*100)
			s1.save()
			return Response(s1.data,status=status.HTTP_201_CREATED)
		return Response(s1.errors, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordView(APIView):

	def post(self,request):
		token = self.request.data['token']
		print(self.request.data['password'])
		password=self.request.data['password']
		user = ResetPasswordToken.objects.filter(key=token).values_list('user_id',flat=True).first()
		u1=User.objects.get(pk=user)
		print(token)
		print(u1)
		print(u1.id)
		data={
			"username":u1.username,
			"email":u1.email,
			"password":make_password(password)
		}
		print(data)
		s1 = userSerializers(u1,data=data)
		if s1.is_valid():
			# s1.password = make_password(password)
			s1.save()
			return Response({"user":user,"message":"password changed Successfully"}) 
		# if not PasswordResetTokenGenerator().check_token(user, token):
		# 	raise ValidationError(invalid_token)
		else:
			return Response({"error":"error occured"}) 


class ChangePasswordView(APIView):
	authentication_classes = [TokenAuthentication]

	def put(self,request):
		token = self.request.data['token']
		psw = self.request.data['old_password']
		n_psw = self.request.data['new_password']
		user = Token.objects.filter(key=token).values_list('user_id',flat=True).first()
		u1=User.objects.get(pk=user)
		print(u1)
		print(psw)
		print(request.data)
		if not u1.check_password(psw):
					return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
		
		data={
			"username":u1.username,
			"email":u1.email,
			"password":make_password(n_psw)
		}

		s1 = userSerializers(u1,data=data)

		if s1.is_valid():
			print(u1)
			s1.save()
			print(s1.data)
			return Response(s1.data)
		else:	
			return Response({"error":"error occured"})

class UserLogoutView(APIView):

	authentication_classes = [TokenAuthentication]

	def post(self, request):
		print(request.META.get('HTTP_AUTHORIZATION'))
		logout(request)
		return Response({"message":'Log Out sucessfully.'},status=204)
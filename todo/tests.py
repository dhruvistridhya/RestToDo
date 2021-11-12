from django.test import TestCase
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.urls import reverse

from rest_framework.test import APIClient

# Create your tests here.
class TestLogin(TestCase):

	def setUp(self):
		self.user = get_user_model().objects.create_user(username="abc", password="python123", email="abc@gmail.com")
		self.user.save()

		self.username = "xyz"
		self.email = "xyz@gmail.com"
		self.password = "python123"

	def test_login(self):
		data={
			"username":"abc",
			"password":"python123"
		}
		u1 = self.client.post(reverse("login"),data=data)
		
		self.assertEqual(u1.status_code,200,"Enter Correct Details")
		print(u1.data['token'])

	def test_register(self):
		u1 = self.client.post(reverse("register"),data={"username":self.username,
														"email":self.email,
														"password":self.password})
		
		self.assertEqual(u1.status_code,201,"Missing Field Error")

	def test_logout(self):
		data={
			"username":"abc",
			"password":"python123"
		}
		u1 = self.client.post(reverse("login"),data=data)
		client = APIClient()
		client.credentials(HTTP_AUTHORIZATION='Token ' + u1.data['token'])

		# session = client.session
		# session['user_token'] = u1.data['token']
		# client.session.save()

		t1 = client.post(reverse('UserLogout'))
		self.assertEqual(t1.status_code,204)
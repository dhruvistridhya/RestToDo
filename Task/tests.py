from django.test import TestCase
from .models import Task
from .serializers import TaskSerializer
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.contrib.auth.models import User


# Create your tests here.

class GetAllTask(TestCase):

	def setUp(self):
		self.user = get_user_model().objects.create_user(username="abc", password="python123", email="abc@gmail.com")
		self.user.save()
		
		# Task.objects.create(title='task1',description='task desc',due_date='2021-09-19')

	def test_getAllTask(self):
		data={
			"username":"abc",
			"password":"python123"
		}
		u1 = self.client.post(reverse("login"),data=data)

		ApiClient = APIClient()
		ApiClient.credentials(HTTP_AUTHORIZATION='Token ' + u1.data['token'])

		response = ApiClient.get('/addTask')		


	def test_addTask(self):
		data={
			"username":"abc",
			"password":"python123"
		}
		u1 = self.client.post(reverse("login"),data=data)

		# ApiClient = APIClient()
		# ApiClient.credentials(HTTP_AUTHORIZATION='Token ' + u1.data['token'])

		session = self.client.session
		session['user_id'] = [u1.data['token']]
		session.save()

		print(session)

		data = {
			"title":'task1',
			"description":"task desc",
			"due_date":'2021-09-19'
		}

		response = self.client.post(reverse('addTask'),data=data)
		self.assertEqual(response.status_code,201)

	def test_updateTask(self):
		data={
			"username":"abc",
			"password":"python123"
		}
		u1 = self.client.post(reverse("login"),data=data)

		session = self.client.session
		session['user_id'] = [u1.data['token']]
		session.save()

		data = {
			'title':'task1',
			'description':'task desc',
			'due_date':'2021-09-19'
		}

		response = self.client.post(reverse('addTask'),data=data)

		print(response)
		task = Task.objects.all().first()
		print(task.id)

		{
			"title":"task22",
			"description":"Update task model",
			"due_date":"2021-09-16"
		}

		response = self.client.put(reverse('editTask',kwargs={"id":task.id}),data=data)
		print(response)

	def test_deleteTask(self):
		data={
			"username":"abc",
			"password":"python123"
		}
		u1 = self.client.post(reverse("login"),data=data)

		session = self.client.session
		session['user_id'] = [u1.data['token']]
		session.save()

		response = self.client.post(reverse('addTask'),data={	"title":'task1',
																"description":"task desc",
																"due_date":'2021-09-19'
															})

		print(response)
		task = Task.objects.all().first()

		response = self.client.delete(reverse('editTask',kwargs={"id":task.id}),data=data)
		print(response)

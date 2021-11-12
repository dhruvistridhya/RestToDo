from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class Task(models.Model):
	title = models.CharField(max_length=20)
	description = models.TextField()
	created = models.DateField(auto_now_add=True)
	due_date = models.DateField(auto_now_add=False)
	completed = models.BooleanField(default=False)
	user = models.ForeignKey(User,on_delete=models.CASCADE)
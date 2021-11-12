from django.contrib import admin
from django.urls import path,include
from .views import TaskView

urlpatterns = [
	path('addTask',TaskView.as_view(),name="addTask"),
	path('editTask/<int:id>',TaskView.as_view(),name="editTask")
]
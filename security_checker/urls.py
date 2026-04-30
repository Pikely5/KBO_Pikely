from django.urls import path
from . import views

app_name = 'security_checker'

urlpatterns = [
    path('', views.index, name='index'),
]
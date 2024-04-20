from django.urls import re_path

from . import views

app_name = 'horcrux'

urlpatterns = [
  re_path(r'^$', views.main, name='main'),
  re_path(r'^shares$', views.shares, name='shares'),
  re_path(r'^combine$', views.combine, name='combine'),
]

from django.conf.urls import url

from . import views

app_name = 'horcrux'

urlpatterns = [
  url(r'^$', views.main, name='main'),
  url(r'^shares$', views.shares, name='shares'),
  url(r'^combine$', views.combine, name='combine'),
]

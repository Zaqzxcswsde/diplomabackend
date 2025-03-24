# file for apps urls 

from django.urls import path

from dplapp import views

urlpatterns = [
    path('mainrequest', views.MainRequestView.as_view()),
    path('canlogin/<uuid:uid>', views.CanLoginView.as_view()),
    path('health/', views.HealthCheckView.as_view()),
]
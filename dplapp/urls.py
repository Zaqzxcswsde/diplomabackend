# file for apps urls 

from django.urls import path, include

from rest_framework.routers import SimpleRouter

from dplapp import views

router = SimpleRouter()
router.register(r'tokens', views.TokenViewSet, basename='token')
router.register(r'history', views.HistoryViewSet, basename='history')
router.register(r'users', views.UserViewSet, basename='user')

urlpatterns = [
    path('mainrequest/', views.MainRequestView.as_view()),
    path('canlogin/<uuid:uid>/', views.CanLoginView.as_view()),
    path('health/', views.HealthCheckView.as_view()),
    path('enforcing-mode/', views.UpdateEnforcingModeView.as_view()),
    path('errors/', views.SearchableErrorsView.as_view())
]

urlpatterns += router.urls
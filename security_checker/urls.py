# Маршруты приложения security_checker

from django.urls import path
from . import views
from . import auth_views          # новые представления для аутентификации
from . import legacy_adapter     # модуль-прокладка для устаревшего формата

app_name = 'security_checker'

urlpatterns = [
    path('', views.index, name='index'),                     # главная страница проверки
    path('login/', auth_views.login_view, name='login'),     # страница входа
    path('logout/', auth_views.logout_view, name='logout'),  # выход
    path('legacy/', legacy_adapter.legacy_check, name='legacy'),  # прокладка для старых систем
]
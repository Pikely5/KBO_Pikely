"""
Django settings for django_project project.

Сгенерировано 'django-admin startproject' с использованием Django 5.0.1.
"""

import os
from pathlib import Path

# Построение путей внутри проекта: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# ПРЕДУПРЕЖДЕНИЕ БЕЗОПАСНОСТИ: храните секретный ключ, используемый в продакшене, в секрете!
SECRET_KEY = 'django-insecure-4ju2n@$f9d0c=h)_g0lbb%k9&@rf(xa$d$g$&5ri$uf)*gev^4'

# ПРЕДУПРЕЖДЕНИЕ БЕЗОПАСНОСТИ: не запускайте с отладкой в продакшене!
DEBUG = True

# Разрешённые хосты из переменной окружения Replit
ALLOWED_HOSTS = os.environ.get("REPLIT_DOMAINS", "*").split(',')

# Доверенные источники для CSRF (основные)
CSRF_TRUSTED_ORIGINS = [
    "https://" + domain for domain in os.environ.get("REPLIT_DOMAINS", "").split(',')
]

# Настройки безопасности для работы через обратный прокси Replit
# (внешний HTTPS, внутри контейнера HTTP)
SECURE_SSL_REDIRECT = False          # Не принуждать к HTTPS (уже на прокси)
SECURE_HSTS_SECONDS = 0             # Отключить HSTS
SESSION_COOKIE_SECURE = False       # Разрешить передачу сессионной куки по HTTP
CSRF_COOKIE_SECURE = False          # Разрешить передачу CSRF-куки по HTTP
# Указать, что за прокси приходит HTTPS, чтобы request.is_secure() работал корректно
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Приложения
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'security_checker',
]

# Промежуточные слои
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
]

# Только в развёрнутом окружении добавляем защиту от Clickjacking
if "REPLIT_DEPLOYMENT" in os.environ:
    MIDDLEWARE.append('django.middleware.clickjacking.XFrameOptionsMiddleware')

ROOT_URLCONF = 'django_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'django_project.wsgi.application'

# База данных SQLite
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Валидаторы паролей
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Язык и время
LANGUAGE_CODE = 'ru-ru'            # Изменено на русский
TIME_ZONE = 'Europe/Moscow'
USE_I18N = True
USE_TZ = True

# Статические файлы (CSS, JavaScript, изображения)
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']

# Тип первичного ключа по умолчанию
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Дополнительные доверенные источники для CSRF (включая HTTP для локальной разработки)
CSRF_TRUSTED_ORIGINS += [
    'https://*.replit.dev',
    'https://*.sisko.replit.dev',
    'http://localhost:8000',
    'http://127.0.0.1:8000',
    'http://0.0.0.0:8000',
]

# URL для перенаправления после входа/выхода
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/'
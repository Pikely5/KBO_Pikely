#!/bin/bash

echo "=========================================="
echo "  Контейнер безопасности облака"
echo "  Проверка соответствия Yandex Cloud"
echo "  Развёртывание в Replit"
echo "=========================================="

# 1. Установка зависимостей
echo ""
echo "[1/6] Установка зависимостей Python..."
pip install django matplotlib --quiet
echo "      Django установлен"
echo "      Matplotlib установлен"

# 2. Создание миграций
echo ""
echo "[2/6] Создание миграций базы данных..."
python manage.py makemigrations security_checker --noinput 2>/dev/null || true
echo "      Миграции созданы"

# 3. Применение миграций
echo ""
echo "[3/6] Применение миграций..."
python manage.py migrate --noinput
echo "      Миграции применены"

# 4. Создание директории для графиков
echo ""
echo "[4/6] Создание директории для графиков..."
mkdir -p static/charts
echo "      Директория static/charts создана"

# 5. Загрузка тестовых данных
echo ""
echo "[5/6] Загрузка тестовых данных..."
python load_data.py
echo "      Данные загружены"

# 6. Создание суперпользователя (если не существует)
echo ""
echo "[6/6] Проверка суперпользователя..."
python -c "
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django
django.setup()
from django.contrib.auth.models import User
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@example.com', 'admin123')
    print('      Суперпользователь создан: admin / admin123')
else:
    print('      Суперпользователь уже существует')
"

# 7. Запуск сервера
echo ""
echo "=========================================="
echo "  Запуск сервера Django..."
echo "  Откройте веб-интерфейс через Webview"
echo "=========================================="
echo ""

python manage.py runserver 0.0.0.0:8000
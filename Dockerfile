# Используем официальный образ Python
FROM python:3.10-slim

# Устанавливаем рабочую директорию внутри контейнера
WORKDIR /app

# Копируем файл зависимостей и устанавливаем их
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь остальной код проекта
COPY . .

# Открываем порт, на котором работает Django
EXPOSE 8000

# Запускаем сервер разработки
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
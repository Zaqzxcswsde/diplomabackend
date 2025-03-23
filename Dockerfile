FROM python:3.12-slim

# Установка зависимостей
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь проект
COPY . .

# Собираем статику (если используется)
RUN python manage.py collectstatic --noinput

# Gunicorn как основной процесс
CMD ["gunicorn", "--workers", "3", "--bind", "0.0.0.0:8000", "dplback.wsgi:application"]
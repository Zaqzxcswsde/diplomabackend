FROM python:3.12-slim

WORKDIR /app

ENV DJANGO_SETTINGS_MODULE=dplback.settings.dev

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x /app/entrypoint.sh

RUN python manage.py collectstatic --noinput

ENTRYPOINT ["/app/entrypoint.sh"]
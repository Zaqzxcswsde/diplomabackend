FROM python:3.12-slim

WORKDIR /app

COPY entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

ENV DJANGO_SETTINGS_MODULE=dplback.settings.dev

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python manage.py collectstatic --noinput

ENTRYPOINT ["/app/entrypoint.sh"]
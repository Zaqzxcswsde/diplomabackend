#!/bin/sh

echo "[INFO] Applying migrations..."
python manage.py migrate

echo "[INFO] Running setup_app..."
python manage.py setup_app

echo "[INFO] Starting Gunicorn..."
gunicorn dplback.wsgi:application --bind 0.0.0.0:8000 --workers 3
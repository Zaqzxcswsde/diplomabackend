#!/bin/sh

set -e

echo "[INFO] Applying migrations..."
if ! python manage.py migrate; then
    echo "[ERROR] Migration failed!"
    exit 1
fi

echo "[INFO] Running setup_app..."
if ! python manage.py setup_app; then
    echo "[ERROR] setup_app failed!"
    exit 1
fi

echo "[INFO] Starting Gunicorn..."
exec gunicorn dplback.wsgi:application --bind 0.0.0.0:8000 --workers 3
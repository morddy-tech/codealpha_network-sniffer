FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=config.settings

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Web app does not need capture privileges. For live packet capture from a
# container you must use host networking and grant raw-socket capabilities
# (CAP_NET_RAW / Npcap inside the container) - see docker-compose.yml notes.
RUN useradd --create-home appuser \
    && mkdir -p /app/logs /app/staticfiles /app/data \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["sh", "-c", "python manage.py migrate && python manage.py collectstatic --noinput && gunicorn config.wsgi:application --bind 0.0.0.0:8000"]

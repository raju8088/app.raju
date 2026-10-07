FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements-hosted.txt .
RUN pip install --no-cache-dir -r requirements-hosted.txt && useradd --create-home --uid 10001 app
COPY --chown=app:app . .
RUN mkdir -p staticfiles && chown app:app staticfiles
USER app
EXPOSE 8000
CMD ["sh", "-c", "python manage.py check --deploy --fail-level WARNING && python manage.py collectstatic --noinput && exec gunicorn omnidim_portal.wsgi:application --bind 0.0.0.0:8000 --workers 2 --threads 4 --timeout 120 --max-requests 1000 --max-requests-jitter 100"]

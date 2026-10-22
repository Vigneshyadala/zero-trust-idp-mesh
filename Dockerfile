FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv

# Run as an unprivileged user, never as root.
RUN useradd --create-home --uid 10001 idp

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# keys/ and data/ are created at runtime and mounted as volumes,
# so the signing key and passkey credentials survive restarts.
RUN mkdir -p keys data && chown -R idp:idp /srv
USER idp

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
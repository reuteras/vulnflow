FROM python:3.15.2-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY vulnflow/ /app/vulnflow/
RUN useradd --system --uid 10001 --home /app vulnflow \
 && mkdir -p /app/data && chown vulnflow /app/data
USER vulnflow
# For `serve` (the webhook receiver); the dt2dojo service turns it off in compose.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["python", "-c", "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('VULNFLOW_PORT','8380')+'/healthz')"]
# .env is provided via env_file in compose; there is no .env file inside the image
ENTRYPOINT ["python", "-m", "vulnflow", "--env-file", "/nonexistent"]

FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY vulnflow/ /app/vulnflow/
RUN useradd --system --uid 10001 --home /app vulnflow \
 && mkdir -p /app/data && chown vulnflow /app/data
USER vulnflow
# .env is provided via env_file in compose; there is no .env file inside the image
ENTRYPOINT ["python", "-m", "vulnflow", "--env-file", "/nonexistent"]

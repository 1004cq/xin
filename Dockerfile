FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 XIN_DATA=/data
WORKDIR /app
COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends fonts-wqy-zenhei && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt && useradd -r -u 10001 xin && mkdir /data && chown xin:xin /data
COPY src/ .
USER xin
EXPOSE 8000
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8000","--no-access-log","--limit-concurrency","40"]

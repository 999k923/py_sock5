FROM python:3.10-slim

WORKDIR /app

# 安装时区数据库（zoneinfo 必须）
RUN apt-get update \
 && apt-get install -y --no-install-recommends tzdata \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY run.py .

# HTTP + SOCKS5
EXPOSE 8008/tcp
EXPOSE 8009/tcp

CMD ["python3", "run.py"]

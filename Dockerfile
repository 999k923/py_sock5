FROM python:3.10-slim

# 工作目录
WORKDIR /app

# 复制程序
COPY requirements.txt .
COPY run.py .

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 8008 是你的程序监听端口
EXPOSE 8008/tcp

# 默认执行 run.py
CMD ["python3", "run.py"]

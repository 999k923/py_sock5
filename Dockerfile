FROM python:3.10-slim

WORKDIR /app

COPY run.py /app/run.py

EXPOSE 8009

CMD ["python3", "run.py"]

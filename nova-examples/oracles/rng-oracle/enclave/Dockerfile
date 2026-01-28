FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV IN_ENCLAVE=True

CMD ["python", "/app/main.py"]

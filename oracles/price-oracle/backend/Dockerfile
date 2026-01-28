FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application and config
COPY app.py .
COPY config.json .
RUN chmod +x app.py

ENV IN_DOCKER=True

# Run the oracle application
CMD ["python", "/app/app.py"]

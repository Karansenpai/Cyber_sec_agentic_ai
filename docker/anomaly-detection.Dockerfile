FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ /app/src/
COPY config/ /app/config/

# Create model storage directory
RUN mkdir -p /app/data/models

# Set environment variables
ENV PYTHONPATH=/app

# Run the anomaly detection service
CMD ["python", "-u", "src/models/anomaly_detection_service.py"]
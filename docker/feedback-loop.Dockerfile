FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and config
COPY src/ /app/src/
COPY config/ /app/config/

# Create directory for VectorDB
RUN mkdir -p /app/data/vector_db
RUN mkdir -p /app/data/models

# Run the feedback loop service
CMD ["python", "-u", "src/models/feedback_loop.py"]
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt bcrypt==4.0.1

COPY . .

ENV PYTHONUNBUFFERED=1

RUN chmod +x start.sh

CMD ["./start.sh"]

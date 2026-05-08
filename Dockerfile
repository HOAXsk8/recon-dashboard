FROM python:3.11-slim

# Install system dependencies, build tools, and scanner requirements
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    pkg-config \
    libc6-dev \
    libmongoc-dev \
    libbson-dev \
    libjson-c-dev \
    libssl-dev \
    libsasl2-dev \
    nmap \
    whatweb \
    ffuf \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install subfinder
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip \
    && apt-get update && apt-get install -y unzip && unzip subfinder_2.6.6_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder_2.6.6_linux_amd64.zip

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt bcrypt==4.0.1

COPY . .

# Compile the C Port Scanner
# We use the discovered paths for headers
RUN gcc tools/scanners/C_port_scanner.c -o tools/scanners/C_port_scanner \
    -I/usr/include/libmongoc-1.0 -I/usr/include/libbson-1.0 -I/usr/include/json-c \
    -lmongoc-1.0 -lbson-1.0 -ljson-c -lpthread

ENV PYTHONUNBUFFERED=1

RUN chmod +x start.sh

CMD ["./start.sh"]

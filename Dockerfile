FROM python:3.11-slim

# Install system dependencies
RUN apt update && apt install -y --no-install-recommends \
    wget \
    ca-certificates \
    nmap \
    ffuf \
    unzip \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Install subfinder
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip \
    && unzip subfinder_2.6.6_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder_2.6.6_linux_amd64.zip

# Install httpx
RUN wget https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip \
    && unzip httpx_1.6.0_linux_amd64.zip \
    && mv httpx /usr/local/bin/ \
    && rm httpx_1.6.0_linux_amd64.zip

# Setup wordlists
RUN mkdir -p /app/wordlists && \
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt \
    -O /app/wordlists/subdomains-top5000.txt && \
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories-lowercase.txt \
    -O /app/wordlists/common-dirs.txt && \
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files-lowercase.txt \
    -O /app/wordlists/common-files.txt

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt bcrypt==4.0.1

COPY . .

ENV PYTHONUNBUFFERED=1

RUN chmod +x start.sh

CMD ["./start.sh"]

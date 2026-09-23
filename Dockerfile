FROM python:3.11-slim

# Install system dependencies
RUN apt update && apt install -y --no-install-recommends \
    wget \
    ca-certificates \
    nmap \
    ffuf \
    unzip \
    whois \
    chromium \
    whatweb \
    && rm -rf /var/lib/apt/lists/*

# Install subfinder and httpx with dynamic architecture detection
RUN ARCH=$(dpkg --print-architecture) && \
    wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_${ARCH}.zip && \
    unzip -o subfinder_2.6.6_linux_${ARCH}.zip && \
    mv subfinder /usr/local/bin/ && \
    rm subfinder_2.6.6_linux_${ARCH}.zip && \
    wget https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_${ARCH}.zip && \
    unzip -o httpx_1.6.0_linux_${ARCH}.zip && \
    mv httpx /usr/local/bin/pd-httpx && \
    rm httpx_1.6.0_linux_${ARCH}.zip

# Install OWASP Amass for passive subdomain enumeration
# Use find to locate the binary after unzip to avoid case-sensitivity issues
# (release zip extracts to amass_Linux_<arch>/ with capital L on some versions)
RUN ARCH=$(dpkg --print-architecture) && \
    AMASS_VERSION="v4.2.0" && \
    wget https://github.com/owasp-amass/amass/releases/download/${AMASS_VERSION}/amass_linux_${ARCH}.zip && \
    unzip -o amass_linux_${ARCH}.zip && \
    find . -maxdepth 2 -type f -name 'amass' -exec mv {} /usr/local/bin/amass \; && \
    chmod +x /usr/local/bin/amass && \
    rm -rf amass_linux_${ARCH}.zip amass_Linux_${ARCH} amass_linux_${ARCH}

# Setup wordlists and screenshots dir
RUN mkdir -p /app/wordlists /app/screenshots && \
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt \
    -O /app/wordlists/subdomains-top5000.txt && \
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files-lowercase.txt \
    -O /app/wordlists/raft-small-files-lowercase.txt && \
    ln -sf /app/wordlists/raft-small-files-lowercase.txt /app/wordlists/raft-small-files.txt && \
    ln -sf /app/wordlists/raft-small-files-lowercase.txt /app/wordlists/common-files.txt && \
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt \
    -O /app/wordlists/DirBuster-2007_directory-list-2.3-small.txt && \
    ln -sf /app/wordlists/DirBuster-2007_directory-list-2.3-small.txt /app/wordlists/directory-list-2.3-small.txt

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt bcrypt==4.0.1

COPY . .

ENV PYTHONUNBUFFERED=1

RUN chmod +x start.sh

CMD ["./start.sh"]

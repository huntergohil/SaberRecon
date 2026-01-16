FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl dnsutils whois nmap git \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
    golang-go ruby ruby-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && mv /root/go/bin/subfinder /usr/local/bin/subfinder

RUN go install -v github.com/OJ/gobuster/v3@latest \
    && mv /root/go/bin/gobuster /usr/local/bin/gobuster

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl dnsutils whois nmap git whatweb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

RUN mkdir -p /data

EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]

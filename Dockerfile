FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl dnsutils whois nmap git \
    golang-go ruby ruby-dev build-essential whatweb \
  && rm -rf /var/lib/apt/lists/*

ARG SUBFINDER_VERSION=v2.6.8
ARG GOBUSTER_VERSION=v3.6.0

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} \
  && mv /root/go/bin/subfinder /usr/local/bin/subfinder

RUN go install -v github.com/OJ/gobuster/v3@${GOBUSTER_VERSION} \
  && mv /root/go/bin/gobuster /usr/local/bin/gobuster

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app
RUN mkdir -p /data

EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]

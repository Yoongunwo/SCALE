FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y \
    auditd \
    audispd-plugins \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY auditd.sh .

RUN chmod +x auditd.sh

CMD ["sleep", "infinity"]
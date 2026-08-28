FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    sysdig

WORKDIR /app

COPY sysdig.sh /app/sysdig.sh
RUN chmod +x /app/sysdig.sh

ENTRYPOINT ["sleep", "infinity"]
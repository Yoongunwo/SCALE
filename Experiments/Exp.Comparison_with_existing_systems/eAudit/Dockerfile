# FROM libbpf image

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# BCC is already installed in the base image. Install only eAudit build/runtime deps.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    kmod \
    python3 \
    sudo \
    time \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/eaudit
COPY . /opt/eaudit

# Normalize line endings for scripts copied from Windows hosts.
RUN sed -i 's/\r$//' /opt/eaudit/ecapd /opt/eaudit/*.sh

RUN make all

COPY docker-entrypoint.sh /usr/local/bin/eaudit-entrypoint
RUN chmod +x /usr/local/bin/eaudit-entrypoint

CMD ["sleep", "infinity"]
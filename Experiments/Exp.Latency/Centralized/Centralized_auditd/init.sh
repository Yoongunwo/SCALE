#!/usr/bin/env bash
set -euo pipefail

echo "[init] installing plugin binary to /usr/local/bin ..."
install -m 0755 /opt/dist/audisp_ts /usr/local/bin/audisp_ts

echo "[init] writing /etc/audit/plugins.d/audisp_ts.conf ..."
mkdir -p /etc/audit/plugins.d
cat >/etc/audit/plugins.d/audisp_ts.conf <<'EOF'
active = yes
direction = out
path = /usr/local/bin/audisp_ts
type = always
format = string
EOF

# auditd 재적용
echo "[init] sending HUP to auditd ..."
pkill -HUP auditd || true

# self-test: 플러그인에 한 줄 흘려보내서 로그파일 생성 확인
echo 'type=SYSCALL msg=audit(1700000000.123456:1) pid=1234 syscall=60 key="selftest"' \
  | /usr/local/bin/audisp_ts || true

echo "[init] last line of /var/log/audisp_ts.log (if any):"
tail -n 1 /var/log/audisp_ts.log || true

: > /var/log/audit/audisp_ts.log
#!/bin/sh
# Restart IDP i for the live preview. Idempotent: leave a healthy server alone.
if curl -sf -o /dev/null --max-time 1 http://127.0.0.1:8080/login; then
  exit 0
fi
cd /workspace
nohup python3 /workspace/idp_i.py --host 0.0.0.0 --port 8080 >>/tmp/idpi-preview.log 2>&1 &
exit 0

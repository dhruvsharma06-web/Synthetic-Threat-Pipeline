#!/usr/bin/env bash
# Start the range. Usage: ./start.sh [--soc]   (--soc adds Wazuh, needs ~8 GB RAM)
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f .env ]; then
  echo "No .env found. Run: cp .env.example .env  and set the passwords." >&2
  exit 1
fi

profiles=(--profile range --profile ui)
if [ "${1:-}" = "--soc" ]; then
  profiles+=(--profile soc)
fi

mkdir -p logs/cowrie logs/vsftpd logs/dvwa logs/sar2html logs/victim
docker compose "${profiles[@]}" up -d --build --wait
docker compose "${profiles[@]}" ps
echo "Range is up. Dashboard: http://localhost:8081   Grafana: http://localhost:3000"

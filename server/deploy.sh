#!/bin/sh
set -e
cd /opt/kingvcam
mkdir -p debug-logs
chmod 755 debug-logs
docker compose up -d --build

#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

echo "Stopping netguard..."
docker compose down

echo "Rebuilding image..."
docker compose build

echo "Starting netguard..."
docker compose up

#echo "Done. Logs:"
#docker compose logs -f

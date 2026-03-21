#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

echo "Stopping netguard..."
docker compose down

echo "Rebuilding image (no cache)..."
docker compose build --no-cache

echo "Starting netguard..."
docker compose up -d

echo "Done. Logs:"
docker compose logs -f

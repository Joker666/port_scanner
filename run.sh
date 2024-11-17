#!/bin/sh

set -e

cd ui && pnpm run build
cd .. && python3 app.py

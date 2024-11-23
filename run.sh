#!/bin/sh

set -e

cd ui && pnpm run build
cd .. && python app.py

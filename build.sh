#!/bin/sh

set -e

cd ui && pnpm install && pnpm run build
cd .. && pip install -r requirements.txt

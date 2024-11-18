#!/bin/sh

set -e

cd ui && pnpm run build
cd .. && pip install -r requirements.txt

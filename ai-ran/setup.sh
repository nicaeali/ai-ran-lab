#!/bin/bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' 'Run this preparation script with sudo.' >&2
    exit 1
fi
mkdir -p /var/log/ai-ran
exec > >(tee -a /var/log/ai-ran/setup.log) 2>&1
exec /usr/bin/python3 "$(dirname "$(readlink -f "$0")")/setup.py"

#!/bin/sh
exec "${PYTHON:-python3}" "$(dirname "$0")/stub_scanner.py" "$@"

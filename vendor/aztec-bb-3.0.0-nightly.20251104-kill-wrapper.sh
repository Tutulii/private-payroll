#!/usr/bin/env bash

# Vendored from AztecProtocol/aztec-packages at commit
# d75a75ed2ec7224a53c78f837205a76f2ad9374e. The pinned bb.js npm artifact
# references this wrapper but does not include it in the published package.

get_ppid_macos() {
  ps -j $$ | awk 'NR==2 {print $3}'
}

get_ppid_linux() {
  awk '{print $4}' /proc/$$/stat
}

is_process_alive_macos() {
  ps -p "$1" > /dev/null 2>&1
}

is_process_alive_linux() {
  [ -d "/proc/$1" ]
}

if [[ "$OSTYPE" == "darwin"* ]]; then
  PARENT_PID=$(get_ppid_macos)
  check_process_alive() { is_process_alive_macos "$1"; }
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
  PARENT_PID=$(get_ppid_linux)
  check_process_alive() { is_process_alive_linux "$1"; }
else
  echo "Unsupported OS" >&2
  exit 1
fi

"$@" &
CHILD_PID=$!

cleanup() {
  kill "$CHILD_PID" 2>/dev/null || true
}

trap cleanup EXIT

while check_process_alive "$PARENT_PID"; do
  sleep 1
done

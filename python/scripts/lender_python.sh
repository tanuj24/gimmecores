#!/bin/bash
# Prints the python3 a lender's sandbox runs for tasks in this environment: the first one on
# PATH that the sandbox can read (system locations, not your home folder or this checkout).
# Trusted mode needs the same Python version on both sides, so its tests run with this one.
set -euo pipefail
IFS=: read -r -a dirs <<< "$PATH"
for d in "${dirs[@]}"; do
  p="$d/python3"
  [ -x "$p" ] || continue
  case "$p" in "$HOME"/* | "$PWD"/*) continue ;; esac
  if [ "$(uname)" = Darwin ]; then
    case "$p" in /usr/* | /bin/* | /opt/homebrew/* | /Library/Frameworks/Python.framework/*) echo "$p"; exit 0 ;; esac
  else
    case "$p" in /usr/* | /bin/* | /sbin/* | /lib* | /opt/*) echo "$p"; exit 0 ;; esac
  fi
done
echo "no python3 a sandbox can run was found on PATH" >&2
exit 1

#!/usr/bin/env bash
# Repeat a run N times and print the median wall time per mode.
# Record your hardware next to the numbers; do not compare with Lambda/Modal.
set -euo pipefail
N=${N:-10}; CODE=${1:-demos/safe.py}
for mode in observe; do
  for i in $(seq "$N"); do
    s=$(date +%s%N); ./bin/tracefuse run --code "$CODE" --mode $mode >/dev/null; e=$(date +%s%N)
    echo $(( (e - s) / 1000000 ))
  done | sort -n | awk -v m=$mode '{a[NR]=$1} END {print m": median "a[int((NR+1)/2)]" ms over "NR" runs"}'
done
uname -a; nproc; free -m | head -2

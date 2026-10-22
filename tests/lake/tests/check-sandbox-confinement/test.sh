#!/usr/bin/env bash
source ../common.sh

if [ "$OS" = Windows_NT ]; then
  echo 'Native Windows behavior tests require the separate prototype driver; see README.md.'
  exit 0
fi
if ! command -v bwrap >/dev/null; then
  echo 'SKIP: behavioral sandbox tests require bubblewrap'
  exit 0
fi
mkdir -p work
c++ -std=c++17 -Wall -Wextra -Werror probe.cpp -o work/probe
python3 run.py --probe work/probe --report work/linux.json \
  --driver lean --run Driver.lean

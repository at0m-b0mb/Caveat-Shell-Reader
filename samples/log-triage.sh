#!/bin/sh
# A long read-only pipeline: find which addresses failed to log in most often.
# Seven stages, so the diagram has to wrap — and nothing here writes anything.
cat /var/log/auth.log | grep 'Failed password' | awk '{print $11}' | sort | uniq -c | sort -rn | head -20

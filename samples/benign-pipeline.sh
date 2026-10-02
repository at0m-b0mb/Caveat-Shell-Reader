#!/bin/sh
# Three stages that only read: list processes, keep the matching lines, print
# the second field of each.
ps aux | grep nginx | awk '{print $2}'

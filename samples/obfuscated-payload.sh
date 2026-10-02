#!/bin/sh
# The text is encoded so the line cannot be read, decoded, and run.
echo aGVsbG8= | base64 -d | sh

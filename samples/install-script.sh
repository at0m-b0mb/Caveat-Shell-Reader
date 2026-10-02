#!/bin/sh
# The shape almost every "quick install" uses. The script is fetched and
# executed as root in the same breath, so nobody ever reads it.
curl -fsSL https://example.com/i.sh | sudo bash

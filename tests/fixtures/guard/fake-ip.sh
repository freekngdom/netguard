#!/bin/sh
# Fake `ip -o -4 addr show`: two docker bridges, so build_xbridge has work to do.
printf '%s\n' \
  '2: br-aaaaaaaaaaaa    inet 10.10.10.1/24 brd 10.10.10.255 scope global br-aaaaaaaaaaaa' \
  '3: br-bbbbbbbbbbbb    inet 10.10.20.1/24 brd 10.10.20.255 scope global br-bbbbbbbbbbbb'

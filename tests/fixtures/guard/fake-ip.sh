#!/bin/sh
# Fake `ip -o -4 addr show`: two br-* bridges plus docker0, whose name does NOT start
# with br-. That is the case that used to be silently excluded from cross-bridge
# isolation, so it belongs in the fixture.
printf '%s\n' \
  '2: br-aaaaaaaaaaaa    inet 10.10.10.1/24 brd 10.10.10.255 scope global br-aaaaaaaaaaaa' \
  '3: br-bbbbbbbbbbbb    inet 10.10.20.1/24 brd 10.10.20.255 scope global br-bbbbbbbbbbbb' \
  '4: docker0            inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0'

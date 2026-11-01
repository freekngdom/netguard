#!/bin/sh
# Fake `docker` CLI: just enough for resolve_alias(). It ignores the network filter
# and the Go template and prints every alias/address pair; the guard filters by alias
# name afterwards, and the fixture aliases are unique.
case "$1" in
  ps)      printf 'c1\nc2\n' ;;
  inspect) printf '%s\n' \
             "traefik 10.10.10.5" \
             "web 10.10.10.10" \
             "web-backend 10.10.20.10" \
             "postgres 10.10.20.5" \
             "db 10.10.20.5" \
             "redis 10.10.20.6" \
             "cache 10.10.20.6" \
             "worker 10.20.0.3" ;;
esac
exit 0

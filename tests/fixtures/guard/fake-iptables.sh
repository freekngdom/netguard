#!/bin/sh
# A fake `iptables` faithful enough to exercise docker-net-guard without root.
#
# State lives in $FAKE_STATE/chains as records:
#   chain:<name>            the chain exists
#   jump:<target>           DOCKER-USER jumps to it
#   raw-hook:<target>       PREROUTING jumps to it
#   rule:<chain>|<rule>     an appended rule, exactly as it was passed
#
# Rules are recorded rather than synthesised, so `-S` reflects what the guard really
# did — which is what its own rule-count and DROP/LOG checks read.
S="${FAKE_STATE:?}"
mkdir -p "$S"
touch "$S/chains"

table=""
op=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -t) table="$2"; shift 2 ;;
    -A|-I|-C|-D|-F|-X|-N|-L|-S) op="$1"; shift ;;
    *) break ;;
  esac
done
chain="$1"

has() { grep -qx "$1" "$S/chains" 2>/dev/null; }
drop() { grep -vx "$1" "$S/chains" > "$S/c" 2>/dev/null; mv "$S/c" "$S/chains"; }

case "$op" in
  -N) has "chain:$chain" || echo "chain:$chain" >> "$S/chains" ;;
  -X) drop "chain:$chain"
      grep -v "^rule:$chain|" "$S/chains" > "$S/c" 2>/dev/null; mv "$S/c" "$S/chains" ;;
  -F) grep -v "^rule:$chain|" "$S/chains" > "$S/c" 2>/dev/null; mv "$S/c" "$S/chains" ;;
  -A) shift
      printf 'rule:%s|%s\n' "$chain" "$*" >> "$S/chains" ;;
  -C)
     shift
     target=""
     while [ "$#" -gt 0 ]; do
       case "$1" in -j) target="$2"; shift 2 ;; *) shift ;; esac
     done
     if [ "$chain" = "PREROUTING" ]; then has "raw-hook:$target"; exit $?
     elif [ "$chain" = "DOCKER-USER" ]; then has "jump:$target"; exit $?
     fi
     exit 1 ;;
  -I)
     shift
     target=""
     while [ "$#" -gt 0 ]; do
       case "$1" in -j) target="$2"; shift 2 ;; *) shift ;; esac
     done
     [ -n "$target" ] || exit 0
     if [ "$chain" = "PREROUTING" ]; then echo "raw-hook:$target" >> "$S/chains"
     else echo "jump:$target" >> "$S/chains"; fi ;;
  -D)
     while [ "$#" -gt 0 ]; do
       case "$1" in -j) drop "jump:$2"; shift 2 ;; *) shift ;; esac
     done ;;
  -L) has "chain:$chain"; exit $? ;;
  -S)
     if [ "$chain" = "DOCKER-USER" ]; then
       echo "-N DOCKER-USER"
       grep '^jump:' "$S/chains" | sed 's/^jump:/-A DOCKER-USER -j /'
       exit 0
     fi
     if [ "$chain" = "PREROUTING" ]; then
       echo "-P PREROUTING ACCEPT"
       grep '^raw-hook:' "$S/chains" | sed 's/^raw-hook:/-A PREROUTING -j /'
       exit 0
     fi
     has "chain:$chain" || exit 1
     echo "-N $chain"
     grep "^rule:$chain|" "$S/chains" | sed "s/^rule:$chain|//" ;;
esac
exit 0

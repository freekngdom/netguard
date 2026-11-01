#!/bin/sh
# A fake `iptables` good enough to exercise docker-net-guard's logic without root or
# a real ruleset. Chains live as lines in $FAKE_STATE/chains; `jump:<target>` records
# a DOCKER-USER hook and `raw-hook:` a PREROUTING jump.
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
  -N) has "$chain" || echo "$chain" >> "$S/chains" ;;
  -X) drop "$chain" ;;
  -F) : ;;
  -C)
     shift
     while [ "$#" -gt 0 ]; do
       case "$1" in -j) target="$2"; shift 2 ;; *) shift ;; esac
     done
     if [ "$chain" = "PREROUTING" ]; then has "raw-hook:$target"; exit $?; fi
     has "jump:$target"; exit $? ;;
  -I)
     shift
     while [ "$#" -gt 0 ]; do
       case "$1" in -j) target="$2"; shift 2 ;; [0-9]*) shift ;; *) shift ;; esac
     done
     if [ "$chain" = "PREROUTING" ]; then echo "raw-hook:$target" >> "$S/chains"
     elif [ -n "$target" ]; then echo "jump:$target" >> "$S/chains"; fi ;;
  -D)
     while [ "$#" -gt 0 ]; do
       case "$1" in -j) drop "jump:$2"; shift 2 ;; *) shift ;; esac
     done ;;
  -L) has "$chain"; exit $? ;;
  -S)
     case "$chain" in
       DOCKER-USER) echo "-N DOCKER-USER"
         grep '^jump:' "$S/chains" | sed 's/^jump:/-A DOCKER-USER -j /' ;;
       DOCKERNET_XBRIDGE) has "$chain" || exit 1
         echo "-N $chain"
         echo "-A $chain -d 10.10.10.1/32 -m comment --comment \"docker-net-guard/xbridge\" -j RETURN"
         echo "-A $chain -d 127.0.0.0/8 ! -i lo -m comment --comment \"docker-net-guard/xbridge\" -j DROP" ;;
       *)
         has "$chain" || exit 1
         echo "-N $chain"
         echo "-A $chain -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment \"docker-net-guard/x\" -j RETURN"
         if [ "${FAKE_OBSERVE:-0}" = 1 ]; then
           echo "-A $chain -m comment --comment \"docker-net-guard/x\" -j LOG"
           echo "-A $chain -m comment --comment \"docker-net-guard/x\" -j RETURN"
         else
           echo "-A $chain -m comment --comment \"docker-net-guard/x\" -j DROP"
         fi ;;
     esac ;;
esac
exit 0

# docker-net-guard — the firewall half.
#
# This container runs in the HOST network namespace because it programs the host's
# iptables: per-network chains in filter/DOCKER-USER and the cross-bridge chain in
# raw/PREROUTING. It needs NET_ADMIN (ruleset), NET_RAW (netlink) and SYSLOG (reading
# would-be-dropped flows out of the kernel ring buffer). It publishes no port, does
# not mount the docker socket, and its rootfs is read-only.
FROM alpine:3.20

# iptables     programs the ruleset (nft backend on current alpine)
# iproute2     `ip -o -4 addr show` — how the cross-bridge chain learns the
#              bridge/subnet set, without asking the Docker API per container
# docker-cli   alias resolution: every poll the guard asks the Engine API which
#              containers carry which alias on each guarded network (DOCKER_HOST)
RUN apk add --no-cache iptables iproute2 docker-cli

COPY docker-net-guard.sh /guard.sh
RUN chmod 0755 /guard.sh && sh -n /guard.sh

# Root is required to program the host ruleset; the container is read-only with all
# capabilities dropped except the ones granted at run time (see docker-compose.yml).
ENTRYPOINT ["/bin/sh", "/guard.sh"]

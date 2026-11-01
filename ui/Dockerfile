# netguard — the UI half.
#
# One stdlib-only Python file: no dependencies, nothing to patch but the base image.
FROM python:3.13-alpine

WORKDIR /app
COPY netguard.py /app/netguard.py

# Unprivileged. The container writes nothing except /data (backups of the config it
# edits, when editing is enabled), so it can run with a read-only root filesystem.
RUN adduser -D -H -u 10001 -s /sbin/nologin netguard \
    && mkdir -p /data /state \
    && chown 10001:10001 /data
USER 10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    LISTEN=0.0.0.0:8080 \
    BACKUP_DIR=/data/backups

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1

CMD ["python3", "-B", "/app/netguard.py"]

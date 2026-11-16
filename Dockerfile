# Zarqa container: non-root, no build tools in the final image.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE config.example.yaml ./
COPY zarqa ./zarqa
RUN pip install --no-cache-dir build && python -m build --wheel -o /dist .

FROM python:3.12-slim
ARG EXTRAS="all"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    ZARQA_HOME=/data ZARQA_BIND_HOST=0.0.0.0 ZARQA_BIND_PORT=8621
COPY --from=build /dist /dist
RUN pip install --no-cache-dir "$(ls /dist/*.whl)[${EXTRAS}]" && rm -rf /dist \
    && groupadd -g 10001 zarqa && useradd -u 10001 -g 10001 -d /data -s /usr/sbin/nologin zarqa \
    && mkdir -p /data && chown zarqa:zarqa /data
USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8621
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8621/healthz',timeout=4).status==200 else 1)"
# First start: writes /data/config.yaml and /data/.env if they are missing, then serves.
CMD ["sh", "-c", "[ -f /data/config.yaml ] || zarqa init; exec zarqa serve"]

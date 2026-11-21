FROM node:22-alpine AS frontend
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WIFI_ANALYZER_HOST=0.0.0.0 \
    WIFI_ANALYZER_PORT=199 \
    HOME=/home/wifi-analyzer \
    XDG_STATE_HOME=/home/wifi-analyzer/.local/state
WORKDIR /app
RUN groupadd --system --gid 10001 wifi-analyzer \
    && useradd --system --uid 10001 --gid wifi-analyzer \
       --home-dir /home/wifi-analyzer --create-home --shell /usr/sbin/nologin wifi-analyzer
COPY wifi_analyzer_backend/requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir -r requirements.txt
COPY --chown=10001:10001 wifi_analyzer_backend/server.py ./server.py
COPY --chown=10001:10001 wifi_analyzer_backend/auth.py ./auth.py
COPY --chown=10001:10001 wifi_analyzer_backend/audit_store.py ./audit_store.py
COPY --chown=10001:10001 wifi_analyzer_backend/audit_checkpoint.py ./audit_checkpoint.py
COPY --chown=10001:10001 wifi_analyzer_backend/live_capture.py ./live_capture.py
COPY --chown=10001:10001 wifi_analyzer_backend/rate_limit.py ./rate_limit.py
COPY --chown=10001:10001 wifi_analyzer_backend/site_history.py ./site_history.py
COPY --chown=10001:10001 wifi_analyzer_backend/report_worker.py ./report_worker.py
COPY --chown=10001:10001 wifi_analyzer_backend/webhook_delivery_store.py ./webhook_delivery_store.py
COPY --chown=10001:10001 wifi_analyzer_backend/webhook_dispatch_worker.py ./webhook_dispatch_worker.py
COPY --chown=10001:10001 wifi_analyzer_backend/router_adapters ./router_adapters
COPY --chown=10001:10001 wifi_analyzer_backend/feature_plugins ./feature_plugins
COPY --from=frontend --chown=10001:10001 /src/dist ./dist
RUN mkdir -p /home/wifi-analyzer/.config/wifi-analyzer-pro \
             /home/wifi-analyzer/.local/state/wifi-analyzer-pro \
    && chown -R 10001:10001 /home/wifi-analyzer
VOLUME ["/home/wifi-analyzer/.config", "/home/wifi-analyzer/.local/state"]
USER 10001:10001
EXPOSE 199
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:199/health', timeout=3)"
CMD ["python", "server.py"]

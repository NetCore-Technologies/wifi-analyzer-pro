FROM node:22-alpine AS frontend
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 WIFI_ANALYZER_HOST=0.0.0.0 WIFI_ANALYZER_PORT=199
WORKDIR /app
COPY wifi_analyzer_backend/requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir -r requirements.txt
COPY wifi_analyzer_backend/server.py ./server.py
COPY --from=frontend /src/dist ./dist
EXPOSE 199
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:199/health', timeout=3)"
CMD ["python", "server.py"]

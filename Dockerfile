# ---------- stage 1: build frontend (alpine) ----------
FROM node:20-alpine AS frontend
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---------- stage 2: runtime (debian slim: glibc needed for Firefox/Camoufox) ----------
FROM python:3.12-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    GITHUB_REGISTER_HOST=0.0.0.0 \
    GITHUB_REGISTER_PORT=8093
WORKDIR /app

# Deps Firefox headful/headless + virtual display + healthcheck.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl xvfb \
        libgtk-3-0 libdbus-glib-1-2 libxt6 libasound2 \
        libnss3 libxss1 libxrandr2 libxcomposite1 libxdamage1 libxfixes3 \
        libpango-1.0-0 libcairo2 libatk1.0-0 libatk-bridge2.0-0 \
        libcups2 libdrm2 libxkbcommon0 libgbm1 fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Wajib sukses: unduh browser Camoufox sekali saat build (bukan tiap start).
RUN python -m camoufox fetch

COPY github_register/ ./github_register/
COPY web/ ./web/
COPY main.py proxy_rotator.py config.example.json ./

COPY --from=frontend /build/dist ./frontend/dist

EXPOSE 8093
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=20s \
    CMD curl -fsS http://127.0.0.1:8093/health || exit 1

# config.json is mounted from the host (see compose); fall back to the example if forgotten.
CMD ["sh", "-c", "test -f config.json || cp config.example.json config.json; exec python -m web.server"]

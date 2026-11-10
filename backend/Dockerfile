FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Headless Chromium for JavaScript-rendered-page discovery (web_layer/js_crawler.py).
# Adds build time and roughly 300-400 MB to the image. This is a per-scan
# opt-in feature (scope_config.use_playwright, default off) — if you never
# use it and want a smaller/faster image, delete this line; the rest of the
# project (including all other URL-based scanning) works unchanged without
# it, and a scan that requests it just records a warning instead of failing.
RUN python -m playwright install --with-deps chromium

COPY . .

RUN chmod +x /app/entrypoint.sh

EXPOSE 8000
CMD ["/app/entrypoint.sh"]

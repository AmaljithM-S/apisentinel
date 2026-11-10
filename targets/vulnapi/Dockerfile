FROM python:3.11-slim

WORKDIR /srv

RUN pip install --no-cache-dir "fastapi==0.115.6" "uvicorn[standard]==0.34.0" "httpx==0.28.1" "pydantic==2.10.4"

COPY app.py /srv/app.py
COPY business_rules.md /srv/business_rules.md

ENV VULNAPI_DB=/tmp/vulnapi.db
EXPOSE 8001

# Bound to the compose network only. This service is intentionally insecure.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8001"]

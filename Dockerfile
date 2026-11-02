# One image for everything: the web app, the sandbox browser (Chromium) and screenshot OCR (Tesseract, English + Hindi).
# Playwright's own image, at the same version as the playwright package, so the browser and its system libraries match.
FROM mcr.microsoft.com/playwright/python:v1.64.1-noble

RUN apt-get update \
 && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng tesseract-ocr-hin \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt
COPY scamcheck ./scamcheck

# Not root: a page that broke out of the browser would land as an ordinary user with nothing to read.
RUN mkdir -p /app/runtime && chown pwuser /app/runtime
USER pwuser
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 SCAMCHECK_ENV=production

# One worker: sessions, the quota windows and the one-browser-at-a-time queue live in this process, and a second
# worker would double the memory on a 512 MB plan. Render sets PORT.
EXPOSE 10000
CMD ["sh", "-c", "exec uvicorn scamcheck.server:app --host 0.0.0.0 --port ${PORT:-10000} --workers 1"]

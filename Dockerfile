# PhantomGuard AI -- production container
# Installs Tamil OCR support (tesseract-ocr-tam) which the dev sandbox this
# was built in couldn't reach over the network -- core/ocr_service.py
# already requests 'eng+tam' and picks it up automatically here.

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-tam \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data

EXPOSE 8000

# Production WSGI server -- the Flask dev server (web/app.py's __main__
# block) explicitly warns against this exact use case.
CMD ["gunicorn", "--chdir", "web", "--bind", "0.0.0.0:8000", "--workers", "2", "app:app"]

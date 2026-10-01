FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

# cabextract opens the LZX-compressed cabinets Windows produces, which the Python reader cannot.
RUN apt-get update && apt-get install -y --no-install-recommends cabextract \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Run as an unprivileged user. The container needs no writable disk beyond /tmp.
RUN useradd --system --uid 10001 analyzer
USER analyzer

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

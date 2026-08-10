FROM python:3.11-slim

# Run as an unprivileged user: the container handles a live GitHub token.
RUN useradd --create-home --uid 10001 auditor

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=auditor:auditor . .
RUN mkdir -p /app/audit_results && chown auditor:auditor /app/audit_results

USER auditor

EXPOSE 5000

ENV PYTHONUNBUFFERED=1 \
    AUDITOR_HOST=0.0.0.0

# There is no authentication in front of this app. Publish the port only to
# localhost: `docker run -p 127.0.0.1:5000:5000 ...`
HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:5000/')" || exit 1

CMD ["python", "app.py"]

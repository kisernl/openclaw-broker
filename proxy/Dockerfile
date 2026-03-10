FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir mitmproxy httpx

COPY addon.py /app/addon.py

# mitmproxy writes its CA cert to /root/.mitmproxy on first run.
# Mount a volume here if you want the cert to persist across deploys
# (required so the sandbox launcher can fetch it).
EXPOSE 8080

CMD ["mitmdump", \
     "-s", "/app/addon.py", \
     "--listen-port", "8080", \
     "--listen-host", "0.0.0.0", \
     "--set", "confdir=/data/certs"]

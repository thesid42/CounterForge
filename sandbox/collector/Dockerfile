FROM python:3.12-alpine
WORKDIR /app
COPY server.py ./
RUN addgroup -S canary && adduser -S canary -G canary && chown -R canary:canary /app
USER canary
EXPOSE 65500
ENV PYTHONUNBUFFERED=1
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:65500/hits')" || exit 1
CMD ["python", "server.py", "65500"]

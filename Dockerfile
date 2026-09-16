FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml domains.yaml ./
COPY certack_utils ./certack_utils
RUN pip install --no-cache-dir . && useradd -r -u 10001 ops
USER ops
EXPOSE 8080
ENTRYPOINT ["certack-utils"]
CMD ["serve"]

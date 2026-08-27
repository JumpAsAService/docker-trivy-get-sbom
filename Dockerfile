ARG TRIVY_VERSION=latest
FROM aquasec/trivy:${TRIVY_VERSION}

RUN apk add --no-cache python3 ca-certificates

ENV TRIVY_CACHE_DIR=/cache \
    PYTHONUNBUFFERED=1 \
    SBOM_FORMAT=cyclonedx \
    SCAN_FORMAT=table \
    SEVERITY=HIGH,CRITICAL \
    IGNORE_UNFIXED=false \
    EXIT_CODE_ON_FINDINGS=0 \
    OUTPUT_DIR=/reports \
    SBOM_DIR=/sbom

RUN mkdir -p /cache /reports /sbom

COPY scanner.py /usr/local/bin/scanner.py
RUN chmod +x /usr/local/bin/scanner.py

# Sovrascrive l'entrypoint originale ("trivy")
ENTRYPOINT ["python3", "/usr/local/bin/scanner.py"]
CMD ["scan"]
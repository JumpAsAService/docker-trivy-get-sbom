# docker-trivy-get-sbom
A simple docker image to get Software Bill of Material (SBOM) using acquasec Trivy and store it in S3 compatible Object Storage

#Example 
docker run --rm \
  -e IMAGES=ghcr.io/aquasecurity/trivy:0.74.0 \
  -v trivy-cache:/cache \
  -v "$PWD/sbom:/sbom" \
  -v "$PWD/reports:/reports" \
  trivy-sbom-scanner:latest

docker run --rm \
  -e IMAGES=ubuntu:latest \
  -e EMBED_VULNS=true \
  -v trivy-cache:/cache -v "$PWD/sbom:/sbom" \
  trivy-scanner:latest
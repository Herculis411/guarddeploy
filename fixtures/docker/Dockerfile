# fixtures/docker/Dockerfile
#
# Intentionally outdated/misconfigured sample image used to demonstrate
# GuardDeploy's Trivy integration. Do not use as a base for real services.

FROM python:3.9-slim-buster

# Misconfiguration: runs as root (no USER directive)
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

EXPOSE 8080
CMD ["python", "app.py"]

# syntax=docker/dockerfile:1

# ---- shared base: the scanner installed into a slim image --------------------
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install . \
 && useradd --create-home --uid 10001 scanner

# ---- seed: synthetic Faker data generator (demo only) ------------------------
FROM base AS seed
RUN pip install "Faker>=24.0"
COPY scripts ./scripts
USER scanner
ENTRYPOINT ["python", "/app/scripts/seed_test_data.py"]

# ---- scanner: the CLI (default target) ---------------------------------------
FROM base AS scanner
USER scanner
WORKDIR /work
ENTRYPOINT ["scanner"]
CMD ["--help"]

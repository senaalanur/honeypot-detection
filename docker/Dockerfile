FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency definition first (better layer caching)
COPY pyproject.toml .
COPY src/ src/

# Install the package
RUN pip install --no-cache-dir -e .

# Non-root user for security
RUN useradd --create-home --shell /bin/bash honeypot
USER honeypot

CMD ["python", "-m", "src.main"]
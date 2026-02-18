FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source and install edr-bench from source
COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir -e .

# The controller is driven by CLI commands; keep the container alive.
CMD ["sleep", "infinity"]

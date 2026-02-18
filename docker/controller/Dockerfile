FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install docker-py for controlling sibling containers via the Docker socket
RUN pip install --no-cache-dir docker

# Install the edr-bench package (expects it to be published or installable)
# If developing locally, mount the source and install in editable mode instead.
RUN pip install --no-cache-dir edr-bench || true

WORKDIR /app

# The controller is driven by CLI commands; keep the container alive.
CMD ["sleep", "infinity"]

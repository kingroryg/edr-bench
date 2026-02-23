FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && DPKG_ARCH=$(dpkg --print-architecture) \
    && DOCKER_ARCH=$([ "$DPKG_ARCH" = "amd64" ] && echo "x86_64" || echo "aarch64") \
    && curl -fsSL "https://download.docker.com/linux/static/stable/${DOCKER_ARCH}/docker-27.5.1.tgz" \
       | tar xz --strip-components=1 -C /usr/local/bin docker/docker \
    && mkdir -p /usr/local/lib/docker/cli-plugins \
    && curl -fsSL "https://github.com/docker/compose/releases/download/v2.32.4/docker-compose-linux-${DOCKER_ARCH}" \
       -o /usr/local/lib/docker/cli-plugins/docker-compose \
    && chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

WORKDIR /app

# Copy source and install edr-bench from source
COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir -e .

# The controller is driven by CLI commands; keep the container alive.
CMD ["sleep", "infinity"]

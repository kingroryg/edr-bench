FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    nginx \
    dnsmasq \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy configuration files
COPY nginx.conf /etc/nginx/nginx.conf
COPY dnsmasq.conf /etc/dnsmasq.conf

# Copy Flask application
COPY app.py /app/app.py

# Copy fake sites
COPY sites/ /var/www/

# Create log directory
RUN mkdir -p /var/log/mocknet

EXPOSE 80 443 53

# NOTE: Make sure entrypoint commands are executable in the build context.
CMD dnsmasq --keep-in-foreground &  \
    nginx &  \
    python3 /app/app.py

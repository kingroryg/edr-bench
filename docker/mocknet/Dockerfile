FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    nginx \
    dnsmasq \
    curl \
    openssh-server \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set up SSH server for scp/sftp scenarios
RUN mkdir -p /run/sshd \
    && useradd -m -s /bin/bash admin \
    && echo "admin:Kx9mP2q" | chpasswd \
    && mkdir -p /var/backups \
    && chown admin:admin /var/backups \
    && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

# Set up bare git repos for git push scenarios
RUN mkdir -p /var/www/git/testuser /var/www/git/meridian-sys \
    && git init --bare /var/www/git/testuser/meridian-api.git \
    && git init --bare /var/www/git/meridian-sys/deploy-pipeline.git \
    && chown -R www-data:www-data /var/www/git

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

EXPOSE 80 443 53 22 8080 8443 8888

# NOTE: Make sure entrypoint commands are executable in the build context.
CMD /usr/sbin/sshd && \
    dnsmasq --keep-in-foreground &  \
    nginx &  \
    python3 /app/app.py

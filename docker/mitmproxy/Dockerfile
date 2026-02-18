FROM mitmproxy/mitmproxy:latest

# Copy custom addon for structured traffic logging
COPY addons/log_traffic.py /home/mitmproxy/addons/log_traffic.py

# Create flows directory
RUN mkdir -p /flows

EXPOSE 8080 8081

CMD ["mitmdump", \
     "--set", "stream_large_bodies=10m", \
     "-s", "/home/mitmproxy/addons/log_traffic.py", \
     "-w", "/flows/traffic.flow", \
     "--web-host", "0.0.0.0", \
     "--web-port", "8081", \
     "--mode", "regular"]

FROM debian:stable
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iptables python3 tcpdump procps && rm -rf /var/lib/apt/lists/*
WORKDIR /lab
ENTRYPOINT ["python3", "/lab/lab.py", "run"]

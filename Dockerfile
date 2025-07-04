FROM ubuntu:22.04

# Set an environment variable to allow non-interactive installation of packages
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    apache2 \
    python3 \
    python3-pip \
    procps \
    sudo \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:password" | chpasswd && \
    adduser testuser sudo

COPY audit_system /audit/audit_system
COPY audit_apache /audit/audit_apache
COPY utils.py /audit/utils.py
COPY main.py /audit/main.py
COPY apache2.conf /etc/apache2/apache2.conf
EXPOSE 80

WORKDIR /var/www/html

# This is the command that will run when the container starts.
# It starts Apache in the foreground, which is necessary to keep the container running.
CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]
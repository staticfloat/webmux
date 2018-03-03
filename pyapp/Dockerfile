FROM python:3

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt; rm -f /tmp/requirements.txt

RUN apt-get update && apt-get install -y socat openssh-client openssh-server

# Allow SSH connections in
RUN mkdir /var/run/sshd
RUN useradd webmux
RUN mkdir -p /home/webmux/.ssh
COPY webmux_rsa.pub /home/webmux/.ssh/authorized_keys
RUN chmod 0600 /home/webmux/.ssh/authorized_keys; \
    chmod 0700 /home/webmux/.ssh; \
    chown webmux:webmux -R /home/webmux

RUN echo "PasswordAuthentication no" >> /etc/ssh/sshd_config; \
    echo "Banner none"               >> /etc/ssh/sshd_config; \
    echo "GatewayPorts yes"          >> /etc/ssh/sshd_config; \
    echo "PrintLastLog no"           >> /etc/ssh/sshd_config

WORKDIR /app
COPY . /app/
CMD ["bash", "start.sh"]
STOPSIGNAL SIGINT

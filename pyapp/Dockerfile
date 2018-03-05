FROM python:3

# Install python requirements
COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt; rm -f /tmp/requirements.txt

# Install various system tools we need
RUN apt-get update && apt-get install -y socat openssh-client openssh-server lsof

# sshd setup
RUN mkdir /var/run/sshd
COPY ./host_keys/ /etc/ssh/
RUN chmod 0600 /etc/ssh/ssh_host*
RUN echo "PasswordAuthentication no"      >> /etc/ssh/sshd_config; \
    echo "Banner none"                    >> /etc/ssh/sshd_config; \
    echo "GatewayPorts yes"               >> /etc/ssh/sshd_config; \
    echo "AllowTcpForwarding yes"         >> /etc/ssh/sshd_config; \
    echo "AllowStreamLocalForwarding yes" >> /etc/ssh/sshd_config; \
    echo "PermitTunnel yes"               >> /etc/ssh/sshd_config; \
    echo "UsePrivilegeSeparation no"      >> /etc/ssh/sshd_config

# Add webmux user who can login
RUN useradd webmux
RUN mkdir -p /home/webmux/.ssh
COPY webmux_rsa.pub /home/webmux/.ssh/authorized_keys
RUN chmod 0600 /home/webmux/.ssh/authorized_keys; \
    chmod 0700 /home/webmux/.ssh; \
    chown webmux:webmux -R /home/webmux

# Add python code
WORKDIR /app
COPY . /app/
CMD ["bash", "start.sh"]
STOPSIGNAL SIGINT

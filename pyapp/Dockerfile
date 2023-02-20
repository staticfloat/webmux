FROM python:3-alpine

# Install python requirements
COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt; rm -f /tmp/requirements.txt

# Install various system tools we need
RUN apk add socat openssh-client openssh-server lsof shadow

# sshd setup
RUN mkdir /var/run/sshd
COPY ./host_keys/ /etc/ssh/
RUN chmod 0600 /etc/ssh/ssh_host*
RUN sed -i "/etc/ssh/sshd_config" -e 's/AllowTcpForwarding no//g' -e 's/GatewayPorts no//g'
RUN echo "PasswordAuthentication no"      >> /etc/ssh/sshd_config; \
    echo "Banner none"                    >> /etc/ssh/sshd_config; \
    echo "GatewayPorts yes"               >> /etc/ssh/sshd_config; \
    echo "AllowTcpForwarding yes"         >> /etc/ssh/sshd_config; \
    echo "AllowStreamLocalForwarding yes" >> /etc/ssh/sshd_config; \
    echo "PermitTunnel yes"               >> /etc/ssh/sshd_config

# Add webmux user who can login
RUN addgroup webmux
RUN adduser -D webmux -G webmux
RUN usermod -p '*' webmux

RUN mkdir -p /home/webmux/.ssh
COPY webmux_rsa.pub /home/webmux/.ssh/authorized_keys
RUN chmod 0600 /home/webmux/.ssh/authorized_keys; \
    chmod 0700 /home/webmux/.ssh; \
    chown webmux:webmux -R /home/webmux

# Add our private key in so that the web in webmux works
RUN mkdir -p /root/.ssh
COPY id_rsa /root/.ssh/
RUN chmod 0600 /root/.ssh/id_rsa && \
    chmod 0700 /root/.ssh

# Add python code
WORKDIR /app
COPY . /app/
ENV SSH_PORT 2000
CMD ["/bin/sh", "start.sh"]
STOPSIGNAL SIGINT

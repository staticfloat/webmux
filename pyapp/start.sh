#!/bin/sh

# When we get killed, kill all our children
trap "exit" INT TERM
trap "kill 0" EXIT

# Start sshd in the background
echo "Starting sshd..."
/usr/sbin/sshd -p ${SSH_PORT}

# start our python app in the background
python webmux.py &
PYTHON_PID=$!
wait $PYTHON_PID

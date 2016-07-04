#!/bin/bash

source secret.sh

function get_port_mapping()
{
    curl -u "$USERNAME:$PASSWORD" -L "https://webmux.e.ip.saba.us/register/$HOSTNAME" 2>/dev/null
}

function webmux_tunnel()
{
    truessh -N -R $1:localhost:22 sabae@saba.us
}

while [ true ]; do
    PORT_NUMBER=$(get_port_mapping)
    echo "Connecting on port $PORT_NUMBER..."
    webmux_tunnel $PORT_NUMBER
    sleep 1
done

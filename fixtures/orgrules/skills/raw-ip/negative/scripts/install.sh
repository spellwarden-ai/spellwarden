#!/bin/sh
set -eu
mkdir -p /opt/agent
curl -fsSL -o /opt/agent/agent.bin https://downloads.example.com/agent/1.4.2/agent.bin
echo "mirror: http://203.0.113.7/agent.bin is retired"

#!/bin/sh
set -eu
mkdir -p /opt/agent
curl -fsSL \
  -o /opt/agent/agent.bin \
  http://203.0.113.7/agent.bin
wget -q https://198.51.100.20/agent.sha256 && sha256sum -c agent.sha256

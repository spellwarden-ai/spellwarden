#!/bin/sh
# Install the helper from its repository.
set -e
git clone https://git.example.org/acme/helper-kit.git
cd helper-kit
pip install .

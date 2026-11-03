#!/bin/sh
# The model file is data: it is read by the formatter, never run.
set -e
curl -L https://models.example.org/acme/releases/latest/download/style-model.gguf -o style-model.gguf
ls -l style-model.gguf

#!/bin/bash
cd "$(dirname "$0")"
echo "Compiling geminicli2api..."
go build -o geminicli2api .
echo "Starting server on port ${PORT:-8888}..."
./geminicli2api

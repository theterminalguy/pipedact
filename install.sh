#!/bin/sh
set -e

# pipedact installer script
echo "🍁 Installing pipedact..."

if command -v go >/dev/null 2>&1; then
    go install github.com/theterminalguy/pipedact/cmd/pipedact@latest
    echo "✔ Successfully installed pipedact via Go!"
    echo "Run 'pipedact --help' to get started."
else
    echo "Error: Go is required to install from source. Please install Go or download a release binary from https://github.com/theterminalguy/pipedact/releases"
    exit 1
fi

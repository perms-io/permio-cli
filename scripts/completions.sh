#!/bin/sh
# Generates shell completion scripts into completions/ for release archives.
set -e
rm -rf completions
mkdir completions
for sh in bash zsh fish; do
  go run ./cmd/permio completion "$sh" > "completions/permio.$sh"
done

#!/bin/sh
set -eu
sudo env DEBIAN_FRONTEND=noninteractive apt-get update -qq
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  build-essential cmake pkg-config libkrb5-dev krb5-user curl ca-certificates
if ! test -x "$HOME/.cargo/bin/rustc"; then
  curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o /tmp/tds-rustup.sh
  sh /tmp/tds-rustup.sh -y --profile minimal --default-toolchain 1.99.1
  rm /tmp/tds-rustup.sh
fi
if ! test -x "$HOME/.local/bin/uv"; then
  install -d "$HOME/.local/bin"
  scratch=$(mktemp -d)
  cd "$scratch"
  asset=uv-x86_64-unknown-linux-gnu.tar.gz
  base=https://github.com/astral-sh/uv/releases/download/0.12.23
  curl -fLsS "$base/$asset" -o "$asset"
  curl -fLsS "$base/$asset.sha256" -o "$asset.sha256"
  sha256sum -c "$asset.sha256"
  tar -xzf "$asset"
  install uv-x86_64-unknown-linux-gnu/uv "$HOME/.local/bin/uv"
  cd /tmp
  rm -rf "$scratch"
fi
"$HOME/.local/bin/uv" python install 3.14.8
"$HOME/.cargo/bin/rustc" --version
"$HOME/.local/bin/uv" --version

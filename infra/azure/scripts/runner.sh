#!/bin/sh
# The Linux runner: names in the domain resolved by its domain controller, Kerberos for the domain, Python and Rust for
# the tests (Rust 1.99.1, the client's minimum). Run on the runner by configure.py.
set -e
domain="$1"; realm=$(echo "$domain" | tr a-z A-Z)
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNS=10.42.1.4\nDomains=~%s\n' "$domain" | sudo tee /etc/systemd/resolved.conf.d/tds.conf >/dev/null
sudo systemctl restart systemd-resolved
sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq krb5-user libkrb5-dev gcc g++ make cmake pkg-config \
    python3-dev rsync >/dev/null
printf '[libdefaults]\n  default_realm = %s\n  dns_lookup_kdc = true\n  rdns = false\n  dns_canonicalize_hostname = false\n[domain_realm]\n  .%s = %s\n' \
    "$realm" "$domain" "$realm" | sudo tee /etc/krb5.conf >/dev/null
command -v uv >/dev/null || curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1
[ -x ~/.cargo/bin/cargo ] || curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain 1.99.1 >/dev/null 2>&1
echo "runner ready: $(getent hosts tdsdc.$domain | awk '{print $1}') is tdsdc.$domain; $(~/.cargo/bin/rustc --version)"

#!/bin/sh
# Public bootstrap only. No account passwords, test credentials or private keys.
set -eu
ssh-keygen -A
curl --fail --silent --show-error -X PUT -H 'Metadata-Flavor: Google' \
  --data-binary @/etc/ssh/ssh_host_ed25519_key.pub \
  http://metadata.google.internal/computeMetadata/v1/instance/guest-attributes/tds/hostkey

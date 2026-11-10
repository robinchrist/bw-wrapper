#!/usr/bin/env bash
# Start the local Vaultwarden test server and make sure alice and bob exist.
# Idempotent: re-running reuses the container/volume and existing accounts.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=env.sh
source "$here/env.sh"

# The fixture root is created and marked here, and only here; every fixture
# tool refuses a root without the marker (safety.py).
python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import safety; safety.create_root(sys.argv[2])' \
  "$here" "$BWW_FIXTURE_ROOT"
tls=$BWW_FIXTURE_ROOT/tls
if [ ! -s "$tls/cert.pem" ] || [ ! -s "$BWW_FIXTURE_CA" ]; then
  mkdir -p "$tls"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=bww-fixture-ca" \
    -keyout "$tls/ca.key" -out "$BWW_FIXTURE_CA" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" \
    -keyout "$tls/key.pem" -out "$tls/cert.csr" 2>/dev/null
  openssl x509 -req -in "$tls/cert.csr" -CA "$BWW_FIXTURE_CA" -CAkey "$tls/ca.key" -CAcreateserial \
    -days 3650 -out "$tls/cert.pem" \
    -extfile <(printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n') 2>/dev/null
  chmod 644 "$tls"/*.pem
  echo "generated TLS CA $BWW_FIXTURE_CA"
  # A container started with an older cert must be recreated (data volume stays).
  docker rm -f "$BWW_CONTAINER" >/dev/null 2>&1 || true
fi

if ! docker container inspect "$BWW_CONTAINER" >/dev/null 2>&1; then
  docker run -d --name "$BWW_CONTAINER" \
    -p 127.0.0.1:18087:80 \
    -v "$BWW_VOLUME":/data \
    -v "$tls":/ssl:ro \
    -e ROCKET_TLS='{certs="/ssl/cert.pem",key="/ssl/key.pem"}' \
    -e SIGNUPS_ALLOWED=true \
    -e SIGNUPS_VERIFY=false \
    -e DOMAIN="$BWW_FIXTURE_URL" \
    -e LOGIN_RATELIMIT_MAX_BURST=1000 -e LOGIN_RATELIMIT_SECONDS=1 \
    -e ADMIN_RATELIMIT_MAX_BURST=1000 \
    vaultwarden/server:latest >/dev/null
  echo "started container $BWW_CONTAINER"
elif [ "$(docker container inspect -f '{{.State.Running}}' "$BWW_CONTAINER")" != true ]; then
  docker start "$BWW_CONTAINER" >/dev/null
  echo "restarted container $BWW_CONTAINER"
fi

# Bounded wait for /alive (max ~60s).
for _ in $(seq 1 120); do
  if curl -sf --cacert "$BWW_FIXTURE_CA" "$BWW_FIXTURE_URL/alive" >/dev/null; then break; fi
  sleep 0.5
done
curl -sf --cacert "$BWW_FIXTURE_CA" "$BWW_FIXTURE_URL/alive" >/dev/null || { echo "vaultwarden did not come up" >&2; exit 1; }
echo "vaultwarden alive at $BWW_FIXTURE_URL"

python3 "$here/vw_api.py" register "$ALICE_EMAIL" "$ALICE_PW"
python3 "$here/vw_api.py" register "$BOB_EMAIL" "$BOB_PW"

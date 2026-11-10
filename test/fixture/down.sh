#!/usr/bin/env bash
# Remove the fixture container, its data volume and /tmp/bww-fixture.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/env.sh"

docker rm -f "$BWW_CONTAINER" >/dev/null 2>&1 && echo "removed container $BWW_CONTAINER" || true
docker volume rm "$BWW_VOLUME" >/dev/null 2>&1 && echo "removed volume $BWW_VOLUME" || true
# Removal goes through the same boundary as every other destructive fixture
# operation: a marked fixture directory that is not a symbolic link.
python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import safety; safety.fixture_path(sys.argv[2])' \
  "$here" "$BWW_FIXTURE_ROOT" || { echo "refusing to remove '$BWW_FIXTURE_ROOT'" >&2; exit 1; }
case $BWW_FIXTURE_ROOT in
  /tmp/bww-fixture) rm -rf "$BWW_FIXTURE_ROOT" && echo "removed $BWW_FIXTURE_ROOT" ;;
  *) echo "refusing to remove '$BWW_FIXTURE_ROOT'" >&2; exit 1 ;;
esac

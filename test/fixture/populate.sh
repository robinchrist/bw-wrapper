#!/usr/bin/env bash
# Fill alice's and bob's fixture vaults using the real bw CLI with isolated
# app-data dirs. Safe to re-run: a vault that already holds the
# "bww-fixture-marker" note is left alone. Leaves both accounts logged in
# and locked.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/env.sh"

curl -sf --cacert "$BWW_FIXTURE_CA" "$BWW_FIXTURE_URL/alive" >/dev/null \
  || { echo "fixture server not running; run up.sh first" >&2; exit 1; }

work=$BWW_FIXTURE_ROOT/work
mkdir -p "$work"
notes=$BWW_FIXTURE_ROOT/populate-notes.txt

# bw ACCOUNT ARGS... : always isolated, never interactive.
b() { local who=$1; shift; fixture_bw "$who" "$@" --nointeraction; }

ensure_login() {
  local who=$1 email pwvar dir
  case $who in
    alice) email=$ALICE_EMAIL pwvar=ALICE_PW dir=$ALICE_APPDATA ;;
    bob) email=$BOB_EMAIL pwvar=BOB_PW dir=$BOB_APPDATA ;;
  esac
  mkdir -p "$dir"
  local st
  st=$(b "$who" status 2>/dev/null | jq -r .status)
  if [ "$st" = unauthenticated ]; then
    b "$who" config server "$BWW_FIXTURE_URL" >/dev/null
    b "$who" login "$email" --passwordenv "$pwvar" --raw >/dev/null
    echo "$who: logged in"
  fi
}

session() { fixture_unlock "$1"; }

id_of() { # ACCOUNT NAME -> id of the unique item with exactly that name
  b "$1" list items --search "$2" | jq -r --arg n "$2" '[.[] | select(.name == $n)][0].id'
}

has_marker() {
  [ "$(b "$1" list items --search bww-fixture-marker | jq length)" -gt 0 ]
}

populate_alice() {
  ensure_login alice
  BW_SESSION=$(session alice); export BW_SESSION
  b alice sync >/dev/null
  if has_marker alice; then
    echo "alice: already populated"
  else
    python3 "$here/gen_vaults.py" alice "$work/alice.json"
    b alice import bitwardenjson "$work/alice.json"
    echo
    b alice sync >/dev/null

    # Trash (soft delete).
    for n in "GitHub old (trashed)" "Trash Me 1" "Trash Me 2" "Trash Me 3" "Trash Me 4"; do
      b alice delete item "$(id_of alice "$n")" >/dev/null
    done
    echo "alice: 5 items moved to trash"

    # Archive (may be unsupported by the server).
    : >"$notes"
    for n in "Archive Me 1" "Archive Me 2"; do
      id=$(id_of alice "$n")
      if out=$(b alice archive item "$id" 2>&1); then rc=0; else rc=$?; fi
      printf 'bw archive item <%s>: rc=%s output=%s\n' "$n" "$rc" "$out" | tee -a "$notes"
    done

    # Attachment.
    printf 'fixture attachment\nline 2\n' >"$work/attachment.txt"
    b alice create attachment --file "$work/attachment.txt" \
      --itemid "$(id_of alice "Attachment Holder")" >/dev/null
    echo "alice: attachment added"

    # Organization with two collections and a few items.
    org=$(python3 "$here/vw_api.py" create-org "$ALICE_EMAIL" "$ALICE_PW" "BWW Test Org" "Shared Infra")
    b alice sync >/dev/null
    printf '{"organizationId":"%s","name":"Shared Marketing","externalId":null,"groups":[],"users":[]}' "$org" \
      | b alice encode | b alice create org-collection --organizationid "$org" >/dev/null
    b alice sync >/dev/null
    infra=$(b alice list org-collections --organizationid "$org" | jq -r '.[] | select(.name=="Shared Infra").id')
    mkt=$(b alice list org-collections --organizationid "$org" | jq -r '.[] | select(.name=="Shared Marketing").id')
    mkorg() { # NAME USER PASS COLLECTION-JSON-ARRAY
      jq -n --arg o "$org" --arg n "$1" --arg u "$2" --arg p "$3" --argjson c "$4" \
        '{organizationId:$o, collectionIds:$c, folderId:null, type:1, name:$n, notes:null,
          favorite:false, reprompt:0, fields:[],
          login:{uris:[{match:null, uri:"https://org.example.test"}], username:$u, password:$p, totp:null}}' \
        | b alice encode | b alice create item >/dev/null
    }
    mkorg "Org Infra DB" dbadmin org-db-pw "[\"$infra\"]"
    mkorg "Org Infra VPN" vpn org-vpn-pw "[\"$infra\"]"
    mkorg "Org Marketing CMS" editor org-cms-pw "[\"$mkt\"]"
    mkorg "Org Shared Both" shared org-both-pw "[\"$infra\",\"$mkt\"]"
    mkorg "GitHub Org" org-gh org-gh-pw "[\"$infra\"]"
    echo "alice: organization $org with 2 collections and 5 items"
  fi
  b alice sync >/dev/null
  b alice lock >/dev/null
  unset BW_SESSION
}

populate_bob() {
  ensure_login bob
  BW_SESSION=$(session bob); export BW_SESSION
  b bob sync >/dev/null
  if has_marker bob; then
    echo "bob: already populated"
  else
    python3 "$here/gen_vaults.py" bob "$work/bob.json"
    b bob import bitwardenjson "$work/bob.json"
    echo
  fi
  b bob sync >/dev/null
  b bob lock >/dev/null
  unset BW_SESSION
}

populate_alice
populate_bob
echo "done; both accounts logged in and locked"

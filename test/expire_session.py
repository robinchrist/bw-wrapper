#!/usr/bin/env python3
"""Make a fixture CLI root look like its login session ended on the server,
without reformatting the data file.

    expire_session.py <app-data-dir> clock|server

clock : the refresh token is past its own expiry (and so is the access token)
server: the refresh token still looks valid, but the server will reject it
        (its payload is altered, so the signature no longer matches)
"""
import base64, json, os, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixture"))
import safety  # noqa: E402

try:
    mode = sys.argv[2]
    # Reading and writing both go through safety: the root must be a marked
    # fixture directory and nothing on the way to data.json may be a link.
    path = os.path.join(sys.argv[1], "data.json")
    raw = safety.read_file(path)
except safety.SafetyError as e:
    sys.exit(f"expire_session.py: {e}")
except OSError as e:
    sys.exit(f"expire_session.py: refusing {sys.argv[1]!r}: {e}")
if mode not in ("clock", "server"):
    sys.exit("usage: expire_session.py <app-data-dir> clock|server")
data = json.loads(raw)


def with_exp(token, delta):
    head, payload, sig = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["exp"] = int(time.time()) + delta
    body = base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode()).decode().rstrip("=")
    return f"{head}.{body}.{sig}"


for key, value in data.items():
    if not isinstance(value, str):
        continue
    if key.endswith("_token_accessToken"):
        raw = raw.replace(json.dumps(value), json.dumps(with_exp(value, -3600)))
    elif key.endswith("_token_refreshToken"):
        raw = raw.replace(json.dumps(value), json.dumps(with_exp(value, -3600 if mode == "clock" else 30 * 86400)))
safety.write_file(path, raw)

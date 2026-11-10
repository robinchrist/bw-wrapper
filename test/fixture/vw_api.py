#!/usr/bin/env python3
"""Minimal Vaultwarden HTTP API client for the bw-wrapper test fixture.

Does the client-side Bitwarden crypto that the bw CLI cannot do for us:
account registration and organization creation. Never talks to any server
other than the local fixture server (BWW_FIXTURE_URL, validated by safety.py).

Usage:
  vw_api.py register EMAIL PASSWORD          # no-op if the account exists
  vw_api.py create-org EMAIL PASSWORD ORGNAME FIRST_COLLECTION
                                             # no-op if an org of that name exists
Requires the 'cryptography' package.
"""
import base64
import hashlib
import hmac
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as apad
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import safety  # noqa: E402

CA = os.environ.get("BWW_FIXTURE_CA", "/tmp/bww-fixture/tls/ca.pem")
try:
    # parsed and validated (scheme, host, port, no user information), not prefix-matched
    URL = safety.fixture_url(os.environ.get("BWW_FIXTURE_URL", "https://127.0.0.1:18087"))
except safety.SafetyError as e:
    sys.exit(f"vw_api.py: {e}")
_opener = None


def _open(req):
    """All requests go through an opener that refuses redirects off the fixture origin."""
    global _opener
    if _opener is None:
        _opener = safety.opener(URL, ssl.create_default_context(cafile=CA))
    return _opener.open(req, timeout=30)


KDF_ITER = 600000
b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731


def http(method, path, body=None, form=None, token=None, accept_json=True):
    headers = {"Accept": "application/json", "Device-Type": "8",
               "Bitwarden-Client-Name": "cli", "Bitwarden-Client-Version": "2026.10.1"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(URL + path, data=data, method=method, headers=headers)
    try:
        with _open(req) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw and accept_json else raw.decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw


# ---- crypto primitives -------------------------------------------------

def master_key(password, email, iters=KDF_ITER):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), email.strip().lower().encode(), iters, 32)


def master_password_hash(mk, password):
    return b64(hashlib.pbkdf2_hmac("sha256", mk, password.encode(), 1, 32))


def stretch(mk):
    enc = HKDFExpand(hashes.SHA256(), 32, b"enc").derive(mk)
    mac = HKDFExpand(hashes.SHA256(), 32, b"mac").derive(mk)
    return enc + mac


def enc_string(key64, plaintext):
    """AES-256-CBC + HMAC-SHA256, Bitwarden EncString type 2."""
    enc, mac = key64[:32], key64[32:]
    iv = os.urandom(16)
    p = padding.PKCS7(128).padder()
    data = p.update(plaintext) + p.finalize()
    e = Cipher(algorithms.AES(enc), modes.CBC(iv)).encryptor()
    ct = e.update(data) + e.finalize()
    tag = hmac.new(mac, iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(tag)}"


def dec_string(key64, s):
    typ, rest = s.split(".", 1)
    if typ != "2":
        raise ValueError(f"unsupported EncString type {typ}")
    iv, ct, tag = (base64.b64decode(x) for x in rest.split("|"))
    enc, mac = key64[:32], key64[32:]
    if not hmac.compare_digest(hmac.new(mac, iv + ct, hashlib.sha256).digest(), tag):
        raise ValueError("EncString MAC mismatch")
    d = Cipher(algorithms.AES(enc), modes.CBC(iv)).decryptor()
    data = d.update(ct) + d.finalize()
    u = padding.PKCS7(128).unpadder()
    return u.update(data) + u.finalize()


def new_keypair(sym_key64):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pkcs8 = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())
    spki = priv.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"encryptedPrivateKey": enc_string(sym_key64, pkcs8), "publicKey": b64(spki)}


# ---- operations --------------------------------------------------------

def prelogin_iters(email):
    st, r = http("POST", "/identity/accounts/prelogin", {"email": email})
    if st != 200:
        return None
    return r.get("kdfIterations") or r.get("KdfIterations")


def login(email, password):
    iters = prelogin_iters(email) or KDF_ITER
    mk = master_key(password, email, iters)
    st, r = http("POST", "/identity/connect/token", form={
        "grant_type": "password", "username": email,
        "password": master_password_hash(mk, password),
        "scope": "api offline_access", "client_id": "cli",
        "deviceType": "8", "deviceIdentifier": str(uuid.uuid5(uuid.NAMESPACE_DNS, "bww-fixture-" + email)),
        "deviceName": "bww-fixture",
    })
    if st != 200:
        sys.exit(f"login failed for {email}: {st} {r}")
    user_key = dec_string(stretch(mk), r["Key"])
    return r["access_token"], user_key


def account_exists(email, password):
    iters = prelogin_iters(email) or KDF_ITER
    mk = master_key(password, email, iters)
    st, _ = http("POST", "/identity/connect/token", form={
        "grant_type": "password", "username": email,
        "password": master_password_hash(mk, password),
        "scope": "api offline_access", "client_id": "cli",
        "deviceType": "8", "deviceIdentifier": str(uuid.uuid5(uuid.NAMESPACE_DNS, "bww-fixture-" + email)),
        "deviceName": "bww-fixture",
    })
    return st == 200


def register(email, password):
    if account_exists(email, password):
        print(f"account {email} already exists")
        return
    st, tok = http("POST", "/identity/accounts/register/send-verification-email",
                   {"email": email, "name": email.split("@")[0], "receiveMarketingEmails": False})
    if st != 200 or not isinstance(tok, str):
        sys.exit(f"send-verification-email failed: {st} {tok}")
    mk = master_key(password, email)
    user_key = os.urandom(64)
    body = {
        "email": email,
        "name": email.split("@")[0],
        "emailVerificationToken": tok,
        "masterPasswordHash": master_password_hash(mk, password),
        "masterPasswordHint": None,
        "key": enc_string(stretch(mk), user_key),
        "kdf": 0, "kdfIterations": KDF_ITER, "kdfMemory": None, "kdfParallelism": None,
        "keys": new_keypair(user_key),
    }
    st, r = http("POST", "/identity/accounts/register/finish", body)
    if st != 200:
        sys.exit(f"register/finish failed: {st} {r}")
    if not account_exists(email, password):
        sys.exit(f"registered {email} but login fails")
    print(f"registered {email}")


def create_org(email, password, name, collection):
    token, user_key = login(email, password)
    st, prof = http("GET", "/api/accounts/profile", token=token)
    for o in prof.get("organizations", []) or prof.get("Organizations", []):
        if o.get("name") == name:
            print(o["id"])
            return
    st, k = http("GET", "/api/accounts/keys", token=token)
    pub = serialization.load_der_public_key(base64.b64decode(k["publicKey"]))
    org_key = os.urandom(64)
    wrapped = pub.encrypt(org_key, apad.OAEP(mgf=apad.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
    body = {
        "name": name, "billingEmail": email, "planType": 0,
        "key": "4." + b64(wrapped),
        "collectionName": enc_string(org_key, collection.encode()),
        "keys": new_keypair(org_key),
    }
    st, r = http("POST", "/api/organizations", body, token=token)
    if st != 200:
        sys.exit(f"create org failed: {st} {r}")
    print(r["id"])


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) == 3 and a[0] == "register":
        register(a[1], a[2])
    elif len(a) == 5 and a[0] == "create-org":
        create_org(*a[1:])
    else:
        sys.exit(__doc__)

#!/usr/bin/env python3
"""Generate deterministic Bitwarden-JSON (unencrypted) import files.

  gen_vaults.py alice OUT.json   # small, edge-case-heavy vault
  gen_vaults.py bob OUT.json     # 3000 logins for performance tests

Items that must be created through other bw commands (trash, archive,
attachment, organization) are handled by populate.sh, not here.
"""
import hashlib
import json
import random
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

FOLDERS = ["Email", "Email Work", "Social", "Finance", "Dev", "Ünïcödé Ordner",
           "Parent/Child", "Empty Folder"]


def fid(name):
    return "f0000000-0000-4000-8000-%012d" % FOLDERS.index(name)


def U(uri, match=None):
    return {"match": match, "uri": uri}


def login(name, username="user", password="pw", uris=(), folder=None, totp=None,
          notes=None, fields=None, history=None, favorite=False, reprompt=0):
    return {
        "type": 1, "name": name, "notes": notes, "favorite": favorite, "reprompt": reprompt,
        "folderId": fid(folder) if folder else None,
        "fields": fields or [],
        "passwordHistory": history,
        "login": {"uris": list(uris) if uris is not None else None, "username": username,
                  "password": password, "totp": totp, "fido2Credentials": []},
    }


def other(typ, name, key, payload, folder=None, notes=None, fields=None):
    d = {"type": typ, "name": name, "notes": notes, "favorite": False, "reprompt": 0,
         "folderId": fid(folder) if folder else None, "fields": fields or []}
    if key:
        d[key] = payload
    return d


def ssh_key(seed):
    k = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())
    priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                           serialization.NoEncryption()).decode()
    pub_raw = k.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                          serialization.PublicFormat.OpenSSH)
    import base64
    blob = base64.b64decode(pub_raw.split()[1])
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return {"privateKey": priv, "publicKey": pub_raw.decode(), "keyFingerprint": fp}


def alice():
    F = lambda n, v, t=0, linked=None: {"name": n, "value": v, "type": t, "linkedId": linked}  # noqa: E731
    items = [
        # --- near-identical names, TOTP forms ---
        login("GitHub", "alice", "gh-pass-1", [U("https://github.com/login")], "Dev",
              totp="JBSWY3DPEHPK3PXP"),
        login("GitHub Work", "alice-work", "gh-work-pass",
              [U("https://github.com", 1)], "Dev",
              totp="otpauth://totp/GitHub%20Work:alice-work?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=60&algorithm=SHA256&issuer=GitHub%20Work"),
        login("github backup", "alice", "gh-backup-pass", [U("github.com")]),
        login("Steam", "alice_steam", "steam-pass", [U("https://store.steampowered.com")],
              "Social", totp="steam://JBSWY3DPEHPK3PXP"),
        login("Invalid TOTP", "alice", "pw-invalid-totp", [U("https://totp-invalid.example.test")],
              totp="not a valid secret!!"),
        login("TOTP otpauth defaults", "alice", "pw-otp-def", [],
              totp="otpauth://totp/Example:alice@example.test?secret=JBSWY3DPEHPK3PXP&issuer=Example"),
        # --- folders sharing substrings ---
        login("Gmail", "alice@gmail.test", "gmail-pw", [U("https://mail.google.com", 0)], "Email"),
        login("Outlook Work", "alice@corp.test", "outlook-pw",
              [U("https://outlook.office.com/mail/", 1)], "Email Work"),
        login("ProtonMail", "alice@proton.test", "proton-pw",
              [U("https://mail.proton.me/u/0/", 2)], "Email"),
        login("Email", "alice@email.test", "email-item-pw", [U("https://email.example.test")],
              "Email Work"),
        # --- URI shapes and match types ---
        login("Exact Match Site", "alice", "exact-pw",
              [U("https://exact.example.test/login?next=%2Fhome", 3)]),
        login("Regex Match Site", "alice", "regex-pw",
              [U(r"^https://[a-z]+\.regex\.example\.test/.*$", 4)]),
        login("Never Match Site", "alice", "never-pw", [U("https://never.example.test", 5)]),
        login("Legacy HTTP", "alice", "http-pw", [U("http://legacy.example.test/")]),
        login("Bare Domain", "alice", "bare-pw", [U("example.com")]),
        login("NAS with port", "admin", "nas-pw", [U("https://nas.local:5001/")]),
        login("Userinfo URI", "alice", "userinfo-pw",
              [U("https://user:secret@userinfo.example.test/path")]),
        login("Router IP", "admin", "router-pw",
              [U("https://192.168.1.1/admin"), U("http://10.0.0.1:8080")], "Finance"),
        login("IPv6 host", "admin", "ipv6-pw", [U("https://[::1]:8443/")]),
        login("Android App", "alice", "android-pw", [U("androidapp://com.example.app")]),
        login("Multi URI", "alice", "multi-pw", [
            U("https://a.multi.example.test", 0), U("https://b.multi.example.test/x", 1),
            U("http://c.multi.example.test:81", 2), U("iosapp://com.example.multi", None)]),
        login("Empty URI list", "alice", "nouri-pw", []),
        login("Null URI list", "alice", "nulluri-pw", None),
        login("URI only", None, None, [U("https://urionly.example.test")]),
        # --- username / password shapes ---
        login("Empty Username", "", "emptyuser-pw", [U("https://emptyuser.example.test")]),
        login("Null Username", None, "nulluser-pw", [U("https://nulluser.example.test")]),
        login("Empty Password", "alice", "", [U("https://emptypw.example.test")]),
        login("Null Password", "alice", None, [U("https://nullpw.example.test")]),
        login("Whitespace Password", "alice", "   ", [U("https://wspw.example.test")]),
        login("Newline Password", "alice", "line1\nline2\n", []),
        login("Unicode Password", "alice", "pässwörd✓€", []),
        login("Long Password", "alice", "x" * 1000, []),
        # --- names ---
        login("Café Müller", "café", "cafe-pw", [U("https://cafe-mueller.example.test")]),
        login("naïve résumé", "alice", "naive-pw", [], "Ünïcödé Ordner"),
        login("日本語サイト", "ユーザー", "nihongo-pw", [U("https://jp.example.test")]),
        login("Emoji 🔑 Vault 🚀", "alice", "emoji-pw", []),
        login('Quote "double" and \'single\'', "alice", "quote-pw", []),
        login(r"Back\slash\name", "alice", "backslash-pw", []),
        login("<tag> & ampersand", "alice", "tag-pw", []),
        login("  padded name  ", "alice", "padded-pw", []),
        login("Duplicate Name", "dup1", "dup-pw-1", []),
        login("Duplicate Name", "dup2", "dup-pw-2", []),
        login("AWS Console", "root", "aws-pw-1", [U("https://console.aws.amazon.com")]),
        login("aws console", "iam-user", "aws-pw-2", [U("https://signin.aws.amazon.com")]),
        login("3f2c1a9e-0000-4000-8000-000000000abc", "guidname", "guid-name-pw", []),
        login("Parent child item", "alice", "child-pw", [], "Parent/Child"),
        login("Social Network", "alice", "social-pw", [U("https://social.example.test")], "Social"),
        login("Bank", "alice", "bank-pw", [U("https://bank.example.test")], "Finance",
              favorite=True, reprompt=1, notes="Reprompt + favorite"),
        # --- notes, fields, history ---
        login("Multi-line Notes", "alice", "notes-pw", [],
              notes="first line\nsecond line\n\n  indented fourth line\ttab"),
        login("Custom Fields", "alice", "fields-pw", [U("https://fields.example.test")], fields=[
            F("text field", "plain value"), F("hidden field", "s3cret-hidden", 1),
            F("bool true", "true", 2), F("bool false", "false", 2),
            F("empty text", ""), F("null text", None),
            F("linked username", None, 3, 100), F("linked password", None, 3, 101),
            F("text field", "duplicate field name"), F("ünïcode field", "wert ✓"),
        ]),
        login("Password History", "alice", "current-pw", [], history=[
            {"lastUsedDate": "2025-01-01T00:00:00.000Z", "password": "old-pw-1"},
            {"lastUsedDate": "2025-06-01T00:00:00.000Z", "password": "old-pw-2"},
            {"lastUsedDate": "2026-01-01T00:00:00.000Z", "password": "old-pw-3"}]),
        login("Attachment Holder", "alice", "attach-pw", []),
        # --- secure notes ---
        other(2, "Secure Note", "secureNote", {"type": 0}, notes="Just a secure note."),
        other(2, "Empty Secure Note", "secureNote", {"type": 0}),
        other(2, "Recovery Codes", "secureNote", {"type": 0}, "Dev",
              notes="code-1\ncode-2\ncode-3", fields=[F("hidden", "hidden-in-note", 1)]),
        # --- cards ---
        other(3, "Visa Card", "card", {"cardholderName": "Alice Example", "brand": "Visa",
              "number": "4111111111111111", "expMonth": "4", "expYear": "2030", "code": "123"},
              "Finance"),
        other(3, "Amex Card", "card", {"cardholderName": "Alice Example", "brand": "Amex",
              "number": "378282246310005", "expMonth": "12", "expYear": "2029", "code": "1234"}),
        other(3, "Amex 34 Card", "card", {"cardholderName": "Alice Example", "brand": "Amex",
              "number": "341111111111111", "expMonth": "1", "expYear": "2031", "code": "4321"}),
        other(3, "Short Number Card", "card", {"cardholderName": None, "brand": None,
              "number": "1234", "expMonth": None, "expYear": None, "code": None}),
        other(3, "Mastercard", "card", {"cardholderName": "A. Example", "brand": "Mastercard",
              "number": "5555555555554444", "expMonth": "7", "expYear": "2028", "code": "999"}),
        # --- identities ---
        other(4, "Full Identity", "identity", {"title": "Ms", "firstName": "Alice",
              "middleName": "B.", "lastName": "Example", "address1": "1 Main St", "address2": None,
              "address3": None, "city": "Berlin", "state": None, "postalCode": "10115",
              "country": "DE", "company": "Example GmbH", "email": "alice@example.test",
              "phone": "+49301234567", "ssn": "000-00-0000", "username": "alice",
              "passportNumber": "P1234567", "licenseNumber": "L-42"}),
        other(4, "Only First Name", "identity", {"firstName": "Alice"}),
        other(4, "Only Last Name", "identity", {"lastName": "Example"}),
        other(4, "No Name Identity", "identity", {"email": "noname@example.test"}),
        # --- ssh keys ---
        other(5, "SSH Key", "sshKey", ssh_key("bww-fixture-ssh-1"), "Dev"),
        other(5, "SSH Key Deploy", "sshKey", ssh_key("bww-fixture-ssh-2")),
        # --- to be trashed / archived by populate.sh ---
        login("GitHub old (trashed)", "alice-old", "gh-old-pw", [U("https://github.com")]),
        login("Trash Me 1", "t1", "trash-pw-1", []),
        login("Trash Me 2", "t2", "trash-pw-2", [], "Email"),
        login("Trash Me 3", "t3", "trash-pw-3", []),
        login("Trash Me 4", "t4", "trash-pw-4", []),
        login("Archive Me 1", "a1", "archive-pw-1", []),
        login("Archive Me 2", "a2", "archive-pw-2", []),
        # marker for idempotency
        other(2, "bww-fixture-marker", "secureNote", {"type": 0}, notes="alice fixture v1"),
    ]
    return {"encrypted": False,
            "folders": [{"id": fid(n), "name": n} for n in FOLDERS],
            "items": items}


def bob(n=3000):
    rnd = random.Random(20261110)
    words = ("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike "
             "november oscar papa quebec romeo sierra tango uniform victor whiskey xray "
             "yankee zulu cloud mail shop bank forum wiki portal admin api dev").split()
    tlds = ["com", "net", "org", "io", "de", "test"]
    folders = ["Folder %02d" % i for i in range(20)]
    fids = ["b0000000-0000-4000-8000-%012d" % i for i in range(20)]
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    items = []
    for i in range(n):
        w1, w2 = rnd.choice(words), rnd.choice(words)
        host = f"{w1}-{w2}{i % 97}.example.{rnd.choice(tlds)}"
        uris = [{"match": None, "uri": f"https://{host}/login"}]
        if rnd.random() < 0.2:
            uris.append({"match": rnd.choice([0, 1, 2, 3]), "uri": f"https://www.{host}/"})
        items.append({
            "type": 1, "name": f"{w1.capitalize()} {w2} {i:04d}",
            "notes": f"generated item {i}" if rnd.random() < 0.3 else None,
            "favorite": rnd.random() < 0.02, "reprompt": 0,
            "folderId": fids[rnd.randrange(20)] if rnd.random() < 0.7 else None,
            "fields": [],
            "login": {"uris": uris, "username": f"{w2}.{w1}{i}@example.test",
                      "password": "".join(rnd.choice(alphabet) for _ in range(rnd.randint(12, 32))),
                      "totp": "JBSWY3DPEHPK3PXP" if rnd.random() < 0.05 else None,
                      "fido2Credentials": []},
        })
    items.append({"type": 2, "name": "bww-fixture-marker", "notes": "bob fixture v1",
                  "favorite": False, "reprompt": 0, "folderId": None, "fields": [],
                  "secureNote": {"type": 0}})
    return {"encrypted": False,
            "folders": [{"id": f, "name": n} for f, n in zip(fids, folders)],
            "items": items}


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("alice", "bob"):
        sys.exit(__doc__)
    data = alice() if sys.argv[1] == "alice" else bob()
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    print(f"{sys.argv[1]}: {len(data['items'])} items, {len(data['folders'])} folders")

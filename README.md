# paperless-ngx-account-takeover
## Why release it
the maintainers thought of the report as slop and just closed the report lol (GHSA-2rmh-7qjw-9gf9)

## Details
Tested on Paperless 3.5.0 docker instance \
Every security-sensitive self-service action on `/api/profile/` executes on
session authentication alone, email and password change with no
current-password proof, pre-change API tokens stay valid after the password
change, an attacker-chosen TOTP secret enrolls (returning recovery codes),
the TOTP factor strips, and you can mint new API tokens mint, all without any password,
OTP, or email proof. \
One hijacked session or leaked token therefore becomes a
persistent, MFA-proof account takeover, and the legitimate user gets no signal
as their old session keeps working too. \
\
**Exploitation requires an existing session token.**
## How to fix
gate these actions behind prompting for the users password and/or a TOTP passcode.
## Severity
8.1 High/`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`.
Network-reachable, low complexity, no user interaction; requires an
authenticated session (low-priv). Same-scope total confidentiality and
integrity loss of the victim account (read all data, change all security
settings, persist past password reset).
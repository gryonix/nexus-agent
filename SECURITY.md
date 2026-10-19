# Security Policy

gryonixNexus manages real servers over SSH and handles credentials (Keychain,
SSH keys, service passwords). If you find a security vulnerability, please
report it privately rather than opening a public issue.

## Reporting a vulnerability

Email **danyil@grypak.com** with:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, or a proof of concept if available.
- The affected version/commit.

You should get a response within a few days. Please give us a reasonable
amount of time to fix the issue before disclosing it publicly.

## Scope

This includes the app itself, the control-plane agent (`gryonixnexusd`), the
generated setup scripts and configs, and the VPN control panel. Issues in
third-party dependencies (mailcow, Nextcloud, Vaultwarden, etc.) should be
reported to those projects directly, unless the vulnerability is in how
gryonixNexus configures or deploys them.

## What the design does NOT protect against

Stated here because a boundary nobody writes down is a boundary somebody
assumes is somewhere else. Each of these is a deliberate choice, and none of
them is a vulnerability to report — a report that one of them is true will be
answered with this section.

**The server-side password vault protects COPIES of the database, not root on
a live machine.** Entries are sealed with XChaCha20-Poly1305 and the key lives
beside them in `/var/lib/gryonixnexus/agent/vault.key`, mode 0600. So a backup,
a snapshot or a lifted disk carries nothing usable; anyone who is already root
on the running host can read the key and the rows both. The install report,
which holds the same credentials, sits next to it as plain text by its own job:
the owner has to be able to read it.

**Signing a device out does not cut off its SSH access.** The session term
(`SetSessionPolicy`) makes the agent refuse a device every RPC until it pairs
again, and removing a device from the paired list takes it out of that
register. Neither touches `authorized_keys`. The SSH key is the actual trust
anchor for every call on this transport, and revoking it is a separate act on
the server. Both apps say this in the same words on the screens that offer it.

**The device identifier is not an authenticator.** `X-Gryonix-Device` tells the
agent which INSTALLATION of the app is calling, so two phones sharing one
exported deployment key can be held apart, expired and listed separately.
Anyone who can already reach the agent can send any value they like; what it
buys is bookkeeping, not authentication.

**Closing password login is conditional on a proven key.** The installer writes
`10-gryonixnexus-no-password.conf` only once the deployment's own key is
present in `authorized_keys` (`grep -qxF`, on that exact key), and never on a
host where the app manages an account it did not create. A host it cannot prove
a key for keeps password login and says so, because locking an owner out of
their own machine is worse than the thing being prevented.

**Credentials on the device live in the platform's own store**, Keychain on
Apple and an AndroidKeyStore-backed store on Android, and never in the export
file. `.gryonixserver` carries the deployment's SSH key by design — that is how
a server moves to a second phone — so treat that file as the key itself.

**The VPN panel container runs as root and has `docker.sock` mounted, by
design.** It needs the socket to drive the protocol containers it manages
(bring clients up and down, read their state) and does not run as an
unprivileged user inside its own image. The consequence is direct: any RCE in
the panel, or any way past its login, is root on the HOST, not merely on the
container — the socket lets the compromised process stand up a privileged
container with `/` mounted in. This is an accepted trade-off, not an
oversight, and narrowing it to a
socket-proxy with a matching allowlist of endpoints is a real option if the
panel's own attack surface ever justifies the added moving part. The
mitigations already in place — PBKDF2-SHA256 login at 200k rounds with a
per-user salt, the fail2ban-style ban/throttle on `client_ip()` (its own
Caddy site overwrites `X-Forwarded-For` so that address cannot be spoofed by
a client), and the admin guard restricting the panel to VPN-only access by
default — are what stand between the internet and this boundary, not a
sandbox around the container itself.

**The control account is root in practice.** The account the app signs in with
may run `/opt/gryonixnexus-agent-bootstrap.sh` as root without a password, and
that wrapper unpacks the agent archive found in the account's home and runs its
`install-agent.sh`. That is how the agent is updated from the app, and it means
anything able to write files as the control user can become root on that
server. The narrow per-command sudo lines elsewhere do not limit this account;
protect its SSH key as you would root's.

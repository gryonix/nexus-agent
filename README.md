# nexus-agent

`gryonixnexusd`, the server agent of [gryonixNexus](https://gryonix.com/nexus/).

It runs on every server the app manages: it keeps the server's state and does
the work, installing and updating mail, VPN, files, photos, passwords and more.
The app reaches it over SSH through a local Unix socket. The agent opens no
port of its own.

## Layout

```
Agent/gryonixnexusd/    the agent (Rust, one static binary)
Agent/bootstrap/        install-agent.sh, run on the server to build and install it
Agent/systemd/          gryonixnexusd.service
Agent/proto/            the API contract the app and the agent share
latest.json             the signed release installed agents update from (main only)
```

## Branches

- `main` is the released agent.
- `beta` is the agent being tried out. It may break.
- `wip` is the agent being worked on right now. It breaks often; for testing only.

In the app, **Sources** on a server's agent page picks where a server takes the agent from:
the copy inside the app, `main`, `beta` or `wip`. The server downloads the branch
and builds it itself.

## Updates

Every installed agent checks `latest.json` on `main`. The file names a tagged
release and its SHA-256, and carries an Ed25519 signature. The agent verifies
the signature against a public key built into it before it downloads anything,
then checks the archive's digest, builds it and restarts.

## License

Source-available, not open source: see [LICENSE](LICENSE). Security reports:
[SECURITY.md](SECURITY.md).

# Third-party components

What this app carries that somebody else wrote, under what terms, and where
its source comes from.

**One entry decides something for the whole product, by being absent**, and
that is why this file exists rather than being a formality:

- **OpenVPN 3, through `OpenVPNAdapter`, is AGPL-3.0 — and it is NOT linked.**
  Linking it would make the combined work AGPL-3.0 and put an App Store build
  out of reach, because Apple's per-device terms are exactly the "further
  restrictions" that license forbids (the VLC precedent, 2011). The App Store
  is a requirement here, so the package is not a
  dependency of any target, `Tools/build-runtimes.sh apple` does not fetch it,
  and `Apple/project.yml` carries the reasoning beside the missing line.
  Everything that IS linked is permissive, which is why [LICENSE](LICENSE) can
  be the project's own source-available license.
- **sagernet/sing is GPL-3.0 and is cut out of xray-core.** xray-core links
  it for Shadowsocks 2022 only, so the build removes that code
  (`Tools/xray-without-sing.py`) and Shadowsocks 2022 comes from this
  repository's own client in `Go/ss2022` instead.
- **xray-core is MPL-2.0**, which is file-level copyleft: it may be part of a
  larger work under another license, and what must stay available is the
  source of ITS files. The build fetches the tree at a pinned tag and
  `Tools/xray-without-sing.py` removes its Shadowsocks 2022 code (two
  directories, two edited files). That script and the pin are the source of
  the modified files, published with this repository. MPL's Exhibit B ("Incompatible With Secondary Licenses") only
  ever bars combination with GPL-family licenses, so under this project's
  license it is not a question this project has to ask.

Everything else below is permissive and imposes only the notice this file is.

## The VPN datapaths

Fetched at pinned tags and built by `Tools/build-runtimes.sh`; the artefacts
are gitignored. The table names every source and its pinned tag.

| Component | License | What it does |
|---|---|---|
| [amneziawg-apple](https://github.com/amnezia-vpn/amneziawg-apple) `v3.1.20260814` | MIT (WireGuard LLC) | WireGuard and AmneziaWG on Apple platforms. One kernel for both. |
| [amneziawg-android](https://github.com/amnezia-vpn/amneziawg-android) `v3.1.20260814` | MIT / Apache-2.0 | the same pair on Android. |
| [amnezia-libxray](https://github.com/amnezia-vpn/amnezia-libxray) `v1.0.2` | MIT | the Xray core's C and Go entry points. Built into the archive above on Apple; built here through `Android/xraybridge` on Android. |
| [xray-core](https://github.com/amnezia-vpn/amnezia-xray-core) `v1.260724.0` | **MPL-2.0** | VLESS/Reality. Built without its Shadowsocks 2022 code; see the notes above. |
| [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) `2.9.3` | MIT | the lwIP stack that turns tunnel packets into SOCKS5 connections for the core above. Vendors lwIP (BSD-3-Clause), libyaml (MIT) and hev-task-system (MIT). |

**OpenVPN is carried on neither platform, and no entry above is OpenVPN's.**
The pinned tags for `OpenVPNAdapter` (AGPL-3.0) and `ics-openvpn` (GPLv2 with
additional terms) are still in `Tools/build-runtimes.sh`, reachable by name,
because a commercial OpenVPN 3 license or a build for somewhere other than the
App Store would make them buildable again. Until such a day nothing fetches
them and nothing links them, so neither license reaches this work. The app
installs and manages OpenVPN on a server and hands the profile to a client app
of the user's choosing — which is a config file, not their code, and carries
no license obligation. "OpenVPN" is their trademark and is used here only to
name the protocol, never in a product name, icon or store listing.

## Swift packages

Resolved by SwiftPM; versions are in `Apple/Packages/gryonixNexus/Package.resolved`.

| Component | License |
|---|---|
| Citadel | MIT |
| BigInt | MIT |
| SwiftTerm | MIT |
| Sparkle (macOS only) | MIT |
| swift-protobuf, swift-nio, swift-nio-ssh, swift-crypto, swift-log, swift-collections, swift-system, swift-asn1, swift-atomics | Apache-2.0 |

## Android libraries

Resolved from Maven Central and Google's repository; versions are in
`Android/gradle/libs.versions.toml`.

| Component | License |
|---|---|
| AndroidX (Compose, activity, lifecycle, navigation, datastore, security, biometric, annotation, collection) | Apache-2.0 |
| Kotlin standard library and coroutines | Apache-2.0 |
| sshj | Apache-2.0 |
| BouncyCastle | MIT-style (Bouncy Castle License) |
| Wire | Apache-2.0 |
| ZXing | Apache-2.0 |

## Services this app INSTALLS on your server

Nothing in this section is linked, shipped or redistributed. The app writes a
compose file naming a published image and the server pulls it — the same
relationship it has with OpenVPN above, and the same conclusion: a
configuration file is not somebody else's code, and their terms do not reach
this work. What the terms DO reach is the person running the server, which is
why the ones that are not plain permissive are named here rather than left to
be discovered.

| Component | License | What it means for somebody running it |
|---|---|---|
| [Open WebUI](https://github.com/open-webui/open-webui) `v0.11.3` | BSD-3-Clause **plus a branding clause** (from v0.6.6) | The "Open WebUI" name and logo may not be removed or obscured unless the deployment stays under 50 users in any 30 days or holds an enterprise license. This catalog installs the published image unmodified and rebrands nothing, so the clause is satisfied by what the install DOES — but it is not the MIT everyone assumes, and silence here would read as if it were. |
| [LiteLLM](https://github.com/BerriAI/litellm) `v1.100.0` | MIT, **with a carve-out** | The repository's own license exempts anything under `enterprise/` and puts it under separate terms. The published image is what this catalog installs, unmodified, and nothing here builds from source or redistributes it — so the carve-out does not reach this work; it is named because "MIT" alone would describe the repository inaccurately. |
| [Ollama](https://github.com/ollama/ollama) `0.33.3` | MIT | Nothing. The MODELS it downloads are a separate question with their own terms — Llama, Gemma and Qwen each carry their own license — which is one more reason the install fetches none and the choice stays the owner's. |
| [AnythingLLM](https://github.com/Mintplex-Labs/anything-llm) `1.16.1` | MIT | Nothing. Worth knowing rather than worth worrying about: the published image bundles an embedding model that runs locally, so ingesting documents needs no third party and sends nothing anywhere — which is the reason this service can work on a deployment with no model provider at all. |
| [Qdrant](https://github.com/qdrant/qdrant) `v1.19.1` | Apache-2.0 | Nothing. The tag pinned here is the plain build; upstream's `-gpu-nvidia` and `-gpu-amd` variants are a different question (drivers on the host) that this catalog does not answer yet. |
| [SearXNG](https://github.com/searxng/searxng) `2026.9.7-3e454637f` | **AGPL-3.0** | The strongest copyleft in this catalog, and the entry that decides what the whole product may claim — so the reasoning is spelled out rather than assumed. Nothing of theirs is linked, carried or redistributed here: the server pulls their published image, and what this repository holds is a compose file plus a four-line settings file **written for it, not copied from it**. That distinction is the whole of it — vendoring their own `settings.yml` to change two keys is the one move that would put an AGPL file in this tree, and upstream's `use_default_settings: true` exists precisely so nobody has to. For the person running it: AGPL's network clause obliges whoever OFFERS the service to make its source available, and an unmodified upstream image is answered by upstream — pointing at their repository is the whole obligation, unless you change their code, in which case your changes travel under the same terms. |
| [OpenClaw](https://github.com/openclaw/openclaw) `2026.9.2` | MIT | Nothing. The messenger accounts it connects to are a separate question with their own terms — WhatsApp, Telegram and Discord each have platform rules about automated accounts — which is one more reason no pairing is made by the install and no token of anybody's passes through this app. |
| [n8n](https://github.com/n8n-io/n8n) `2.37.10` | **Sustainable Use License** — not an open-source license | The one entry in this catalog whose terms are not permissive, which is exactly why it is named. Internal business use and modification are allowed without limit; what is NOT allowed is hosting it for other people as a service, or reselling it. Installing it on your own server for your own workflows — which is the only thing this catalog does — is squarely inside those terms. If you intend to run workflows FOR customers on it, read the license first: that is the case it is written to catch. |

Every other image the catalog installs is pinned by exact tag in
`ServiceCatalog`'s own service files, and their terms are permissive — the
PostgreSQL beside n8n is stock `postgres:16-alpine` under the PostgreSQL
license, the same image three other services here already use.

## The agent

`Server/gryonixnexusd` is this project's own code under the same license as the
rest. Its Rust dependencies are listed in `Cargo.toml` and pinned in
`Cargo.lock`; they are Apache-2.0 or MIT.

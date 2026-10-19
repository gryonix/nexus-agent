#!/bin/sh
# Idle while Caddy serves no.local names; installs avahi the first time it needs
# it.
set -u

CADDYFILE="${GRYONIXNEXUS_CADDYFILE:-/etc/caddy/Caddyfile}"
INTERVAL="${GRYONIXNEXUS_MDNS_INTERVAL:-30}"
NFT_DIR="${GRYONIXNEXUS_NFT_DIR:-/etc/nftables.d}"
NFT_CHAIN="inet filter gryonixnexus_services"

log() { printf 'gryonixnexus-mdns: %s\n' "$*" >&2; }

# Names from site block headers, minus the machine's own (avahi's already)
site_names() {
  [ -r "$CADDYFILE" ] || return 0
  own="$(hostname 2>/dev/null | cut -d. -f1 | tr 'A-Z' 'a-z').local"
  grep -E '^[^[:space:]#][^#]*\{[[:space:]]*$' "$CADDYFILE" |
    tr ', {' '\n\n\n' |
    sed -e 's#^[a-z]*://##' -e 's#/.*$##' -e 's#:[0-9]*$##' |
    tr 'A-Z' 'a-z' |
    grep -E '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.local$' |
    grep -vxF "$own" |
    sort -u
}

# Tunnels, bridges and containers never face the home network
faces_lan() {
  case "$1" in
    lo|wg*|awg*|tun*|tap*|tailscale*|ts*|zt*|nb*|docker*|br-*|veth*|virbr*|cni*|flannel*|kube*|gryonix*) return 1 ;;
  esac
  return 0
}

# First IPv4 address of one interface
address_of() {
  ip -4 -o addr show dev "$1" scope global 2>/dev/null |
    awk '{sub("/.*", "", $4); print $4; exit}'
}

# The LAN address, even when a VPN holds the default route
primary_ip() {
  for dev in $(ip -4 route show default 2>/dev/null |
      awk '{m = 0; for (i = 1; i < NF; i++) { if ($i == "dev") d = $(i + 1); if ($i == "metric") m = $(i + 1) } print m, d}' |
      sort -n | awk '{print $2}'); do
    faces_lan "$dev" || continue
    addr="$(address_of "$dev")"
    [ -n "$addr" ] && { printf '%s' "$addr"; return 0; }
  done
  addr="$(ip -4 -o addr show scope global 2>/dev/null |
    while read -r _ dev _ cidr _; do
      if faces_lan "$dev"; then printf '%s\n' "${cidr%/*}"; break; fi
    done)"
  [ -n "$addr" ] || addr="$(ip -4 route get 1.1.1.1 2>/dev/null |
    awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')"
  [ -n "$addr" ] || addr="$(hostname -I 2>/dev/null | awk '{print $1}')"
  printf '%s' "$addr"
}

ensure_avahi() {
  command -v avahi-publish >/dev/null 2>&1 && return 0
  [ -z "${tried_install:-}" ] || return 1
  tried_install=1
  command -v apt-get >/dev/null 2>&1 || { log "avahi-publish is missing and apt-get is not here"; return 1; }
  log "installing avahi to publish the .local names"
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y avahi-daemon avahi-utils >/dev/null 2>&1 ||
    { apt-get update >/dev/null 2>&1 && apt-get install -y avahi-daemon avahi-utils >/dev/null 2>&1; } ||
    { log "installing avahi failed"; return 1; }
  systemctl enable --now avahi-daemon >/dev/null 2>&1 || true
  command -v avahi-publish >/dev/null 2>&1
}

# The firewall drops mDNS questions unless a rule lets them in
open_mdns() {
  [ -d "$NFT_DIR" ] && command -v nft >/dev/null 2>&1 || return 0
  nft list chain $NFT_CHAIN >/dev/null 2>&1 || return 0
  rules="$NFT_DIR/gryonixnexus-svc-mdns.nft"
  [ -f "$rules" ] || cat > "$rules" <<RULES
# Managed by gryonixNexus — ports opened for mdns by gryonixnexusd.
# Included by /etc/nftables.conf; do not edit by hand.
add rule $NFT_CHAIN ip daddr 224.0.0.251 udp dport 5353 accept comment "mdns"
add rule $NFT_CHAIN ip6 daddr ff02::fb udp dport 5353 accept comment "mdns"
RULES
  nft list chain $NFT_CHAIN 2>/dev/null | grep -q 'comment "mdns"' && return 0
  printf 'flush chain %s\ninclude "%s/gryonixnexus-*.nft"\n' "$NFT_CHAIN" "$NFT_DIR" | nft -f - &&
    log "opened mDNS (udp 5353) in the firewall"
}

children=""

stop_all() {
  for pid in $children; do kill "$pid" 2>/dev/null; done
  children=""
}

# A publisher dies when avahi restarts; then all are started again
all_alive() {
  for pid in $children; do kill -0 "$pid" 2>/dev/null || return 1; done
}

publish() {
  addr="$1"; shift
  for name in "$@"; do
    avahi-publish -a -R "$name" "$addr" >/dev/null 2>&1 &
    children="$children $!"
  done
  log "publishing $* at $addr"
}

trap 'stop_all; exit 0' TERM INT

last=""
while :; do
  names="$(site_names | tr '\n' ' ')"
  addr="$(primary_ip)"
  [ -z "${names% }" ] || open_mdns
  state="$addr $names"
  if [ "$state" != "$last" ] || ! all_alive; then
    stop_all
    last="$state"
    if [ -n "${names% }" ] && [ -n "$addr" ]; then
      # shellcheck disable=SC2086 # one argument per name
      if ensure_avahi; then publish "$addr" $names; else last=""; fi
    fi
  fi
  if [ -n "${GRYONIXNEXUS_MDNS_ONCE:-}" ]; then wait; exit 0; fi
  sleep "$INTERVAL" &
  wait $!
done

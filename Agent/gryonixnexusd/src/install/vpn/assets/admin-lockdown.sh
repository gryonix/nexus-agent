#!/bin/bash
# Managed by gryonixNexus — VPN-only access switch for admin web panels.
# on = every site; only host... = just those sites (per-service
# selection); off = public again. Every Caddy site imports the guard,
# so a host matcher inside it narrows which vhosts actually block.
set -euo pipefail
GUARD=/etc/caddy/gryonixnexus-admin-guard
NOVPN="$GUARD.novpn"
# Shown to blocked visitors so a locked panel is a clear "denied"
# page, not an empty-bodied 403 that browsers render as a blank
# white screen. It names WireGuard specifically: whoever reads this
# page is most often already connected to the VPN — on AmneziaWG or
# one of the proxy protocols, which do not carry admin traffic — so
# "connect to the VPN" would be advice they already followed.
# ASCII only and no quotes: it rides through a Caddyfile heredoc and
# lands inside a double-quoted respond argument.
DENY='Access denied. The admin panels are reachable only over the VPN. Connect to your VPN and try again.'
DENY_HOME='Access denied. This site is reachable only from the home network.'
reload_caddy() { systemctl reload caddy 2>/dev/null || systemctl restart caddy || true; }
write_guard() {
  hosts="$1"
  novpn=""
  if [ -s "$NOVPN" ]; then
    for n in $(cat "$NOVPN"); do
      if [ -z "$hosts" ]; then
        novpn="$novpn $n"
      else
        case " $hosts " in *" $n "*) novpn="$novpn $n" ;; esac
      fi
    done
  fi
  # Scenario-A hairpin allow-source. VPN clients on the containerised
  # protocols (amneziaWG / OpenVPN / shadowsocks / xray) that open an
  # admin panel served on THIS host's own public IP loop back through
  # the protocol/host NAT and reach Caddy SNAT'd to that public IP — a
  # source private_ranges does not cover, so the guard used to 403 a
  # genuinely VPN-side client (only the panel's own WireGuard, which
  # arrives from a private address, got through). No off-box client can
  # forge our own public IP as its source — the TCP return path comes
  # straight back to us — so our own global addresses are a safe allow.
  # This is the scenario-A counterpart to the 10.8.0.254 relay hairpin.
  selfip=$(
    { ip -4 -o addr show scope global; ip -6 -o addr show scope global; } 2>/dev/null \
      | awk '{ split($4, a, "/"); ip = a[1]; print ip (index(ip, ":") ? "/128" : "/32") }' \
      | paste -sd' ' -
  )
  # Cloudflare Tunnel visitors come from loopback; its header marks them.
  {
    if [ -n "$hosts" ]; then
      printf '@gryonixnexus_relay {\n'
      printf '    host %s\n' "$hosts"
      printf '    remote_ip 10.8.0.0/24\n'
      printf '    not remote_ip 10.8.0.254/32\n'
      printf '}\n'
      printf 'respond @gryonixnexus_relay "%s" 403\n' "$DENY"
      printf '@gryonixnexus_public {\n'
      printf '    host %s\n' "$hosts"
      printf '    not remote_ip private_ranges %s\n' "$selfip"
      printf '}\n'
      printf 'respond @gryonixnexus_public "%s" 403\n' "$DENY"
      printf '@gryonixnexus_tunnel {\n'
      printf '    host %s\n' "$hosts"
      printf '    header Cf-Connecting-IP *\n'
      printf '}\n'
      printf 'respond @gryonixnexus_tunnel "%s" 403\n' "$DENY"
    else
      printf '@gryonixnexus_relay {\n'
      printf '    remote_ip 10.8.0.0/24\n'
      printf '    not remote_ip 10.8.0.254/32\n'
      printf '}\n'
      printf 'respond @gryonixnexus_relay "%s" 403\n' "$DENY"
      printf '@gryonixnexus_public not remote_ip private_ranges %s\n' "$selfip"
      printf 'respond @gryonixnexus_public "%s" 403\n' "$DENY"
      printf '@gryonixnexus_tunnel header Cf-Connecting-IP *\n'
      printf 'respond @gryonixnexus_tunnel "%s" 403\n' "$DENY"
    fi
    if [ -n "$novpn" ]; then
      printf '@gryonixnexus_novpn {\n'
      printf '    host %s\n' "${novpn# }"
      printf '    remote_ip 10.8.0.0/24 10.9.0.0/24 10.10.0.0/24 10.11.0.0/24 %s\n' "$selfip"
      printf '}\n'
      printf 'respond @gryonixnexus_novpn "%s" 403\n' "$DENY_HOME"
    fi
  } > "$GUARD"
  reload_caddy
}
case "${1:-status}" in
  on)
    write_guard ""
    echo on ;;
  only)
    shift
    [ "$#" -ge 1 ] || { echo "usage: $0 only host... [--no-vpn host...]" >&2; exit 64; }
    list=""
    deny=""
    setdeny=0
    for h in "$@"; do
      if [ "$h" = "--no-vpn" ]; then setdeny=1; continue; fi
      case "$h" in
        *[!A-Za-z0-9.-]*|"") echo "invalid host: $h" >&2; exit 64 ;;
      esac
      if [ "$setdeny" = 1 ]; then deny="$deny $h"; else list="$list $h"; fi
    done
    [ -n "$list" ] || { echo "usage: $0 only host... [--no-vpn host...]" >&2; exit 64; }
    if [ "$setdeny" = 1 ]; then printf '%s' "${deny# }" > "$NOVPN"; fi
    write_guard "${list# }"
    echo "only ${list# }" ;;
  off)
    : > "$GUARD"
    reload_caddy
    echo off ;;
  status)
    body=$(sed '/^@gryonixnexus_novpn/,$d' "$GUARD" 2>/dev/null || true)
    if [ ! -s "$GUARD" ]; then
      echo off
    elif grep -q 'host ' <<< "$body"; then
      echo "only $(grep -m1 'host ' <<< "$body" | sed 's/^ *host //')"
    else
      echo on
    fi ;;
  *)
    echo "usage: $0 on|off|only host... [--no-vpn host...]|status" >&2; exit 64 ;;
esac

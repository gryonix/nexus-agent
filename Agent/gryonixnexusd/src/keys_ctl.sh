#!/bin/bash
# Managed by gryonixNexus: adds and removes tagged lines in a control user's authorized_keys.
# Only lines carrying the ` # gnx:` marker are ever touched.
set -euo pipefail
action="${1:-}"
user="${2:-}"
home="${GNX_TEST_HOME:-$(getent passwd "$user" | cut -d: -f6)}"
[ -n "$home" ] && [ -d "$home" ] || { echo "no home for $user" >&2; exit 2; }
dir="$home/.ssh"
file="$dir/authorized_keys"
install -d -m 700 "$dir"
[ -n "${GNX_TEST_HOME:-}" ] || chown "$user" "$dir" 2>/dev/null || true
[ -e "$file" ] || { : > "$file"; chmod 600 "$file"; [ -n "${GNX_TEST_HOME:-}" ] || chown "$user" "$file" 2>/dev/null || true; }
exec 9>"$dir/.gnx.lock"
flock 9
now="$(date +%s)"
rewrite() {
  local tmp
  tmp="$(mktemp "$dir/.gnx.XXXXXX")"
  awk -v tag="$1" -v now="$now" '
    function tagged(line) { return index(line, " # gnx:") > 0 }
    {
      if (!tagged($0)) { print; next }
      rest = substr($0, index($0, " # gnx:") + 7)
      split(rest, parts, " ")
      name = parts[1]
      expiry = 0
      if (match(rest, / exp=[0-9]+/)) expiry = substr(rest, RSTART + 5, RLENGTH - 5) + 0
      if (tag != "" && name == tag) next
      if (expiry > 0 && expiry < now) next
      print
    }' "$file" > "$tmp"
  cat "$tmp" > "$file"
  rm -f "$tmp"
}
case "$action" in
  add)
    tag="${3:-}"; kind="${4:-}"; blob="${5:-}"; expiry="${6:-0}"
    [ -n "$tag" ] && [ -n "$kind" ] && [ -n "$blob" ] || exit 2
    rewrite ""
    if awk -v blob="$blob" '$1 == "ssh-ed25519" && $2 == blob { found = 1 } $2 == blob { found = 1 } END { exit found ? 0 : 1 }' "$file"; then
      exit 3
    fi
    if [ "$expiry" -gt 0 ] 2>/dev/null; then
      printf '%s %s # gnx:%s exp=%s\n' "$kind" "$blob" "$tag" "$expiry" >> "$file"
    else
      printf '%s %s # gnx:%s\n' "$kind" "$blob" "$tag" >> "$file"
    fi
    ;;
  remove)
    tag="${3:-}"
    [ -n "$tag" ] || exit 2
    before="$(grep -c ' # gnx:' "$file" || true)"
    rewrite "$tag"
    after="$(grep -c ' # gnx:' "$file" || true)"
    [ "$before" -gt "$after" ] || exit 4
    ;;
  prune)
    rewrite ""
    ;;
  *)
    echo "unknown action" >&2
    exit 2
    ;;
esac

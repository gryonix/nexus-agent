#!/bin/bash
# Managed by gryonixNexus — the server's own packages, now, at start or shutdown.
# Usage: gryonixnexus-system-ctl.sh status
#        gryonixnexus-system-ctl.sh start
#        gryonixnexus-system-ctl.sh at-start <system|apps> <on|off>
#        gryonixnexus-system-ctl.sh at-stop <system|apps> <on|off>
#        gryonixnexus-system-ctl.sh swap <1-256|off>
#        gryonixnexus-system-ctl.sh schedule <off|every:<n>h@HH:MM|every:<n>d@HH:MM>
#        gryonixnexus-system-ctl.sh run | boot-run | stop-run | scheduled-run
set -euo pipefail

SELF=/opt/gryonixnexus-system-ctl.sh
JOB=gryonixnexus-system-update
LOG=/var/log/gryonixnexus-system-update.log
CONF=/etc/gryonixnexus/update-at-start.conf
UNIT_NAME=gryonixnexus-update-at-start.service
UNIT=/etc/systemd/system/$UNIT_NAME
STOP_UNIT_NAME=gryonixnexus-update-at-stop.service
STOP_UNIT=/etc/systemd/system/$STOP_UNIT_NAME
APPS=/opt/gryonixnexus-update-ctl.sh
EXIT_MARK=GRYONIXNEXUS_SYSTEM_EXIT
SWAPFILE=/swapfile-gryonixnexus
SCHEDULE_CONF=/etc/gryonixnexus/system-schedule.conf
TIMER_NAME=gryonixnexus-system-scheduled.timer
TIMER=/etc/systemd/system/$TIMER_NAME
SCHEDULED_NAME=gryonixnexus-system-scheduled.service
SCHEDULED=/etc/systemd/system/$SCHEDULED_NAME

# Packages only; configuration files the owner changed are kept.
upgrade() {
  export DEBIAN_FRONTEND=noninteractive
  echo "## apt-get update"
  apt-get update -q
  echo "## apt-get upgrade"
  apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade
  apt-get -y -q autoremove
}

is_on() { grep -qx "$1=on" "$CONF" 2>/dev/null; }

is_running() { systemctl is-active --quiet "$JOB" || systemctl is-active --quiet "$SCHEDULED_NAME"; }

status() {
  if is_running; then echo "state=running"; else echo "state=idle"; fi
  echo "exit=$(sed -n "s/^$EXIT_MARK:\([0-9]*\)$/\1/p" "$LOG" 2>/dev/null | tail -n 1)"
  echo "finished=$(stat -c %Y "$LOG" 2>/dev/null || echo 0)"
  echo "reboot=$([ -f /var/run/reboot-required ] && echo yes || echo no)"
  echo "system=$(is_on system && echo on || echo off)"
  echo "apps=$(is_on apps && echo on || echo off)"
  echo "system_stop=$(is_on system_stop && echo on || echo off)"
  echo "apps_stop=$(is_on apps_stop && echo on || echo off)"
  echo "swap=$(awk '/^SwapTotal:/ {printf "%.0f", $2 * 1024}' /proc/meminfo)"
  echo "swapfile=$(stat -c %s "$SWAPFILE" 2>/dev/null || echo 0)"
  echo "schedule=$(sed -n 's/^schedule=//p' "$SCHEDULE_CONF" 2>/dev/null | tail -n 1 | grep . || echo off)"
  echo "log:"
  tail -n 80 "$LOG" 2>/dev/null || true
}

start() {
  if ! is_running; then
    systemctl reset-failed "$JOB" >/dev/null 2>&1 || true
    : > "$LOG"
    chmod 644 "$LOG"
    systemd-run --unit="$JOB" --collect --quiet \
      /bin/bash -c "'$SELF' run >>'$LOG' 2>&1; echo $EXIT_MARK:\$? >>'$LOG'"
  fi
  status
}

write_unit() {
  cat > "$UNIT" <<EOF_UNIT
[Unit]
Description=gryonixNexus updates at start
Wants=network-online.target
After=network-online.target docker.service
[Service]
Type=oneshot
ExecStart=$SELF boot-run
TimeoutStartSec=2h
[Install]
WantedBy=multi-user.target
EOF_UNIT
  systemctl daemon-reload
  systemctl enable "$UNIT_NAME" >/dev/null 2>&1
}

drop_unit() {
  systemctl disable "$UNIT_NAME" >/dev/null 2>&1 || true
  rm -f "$UNIT"
  systemctl daemon-reload
}

# Stops before the network and docker do, so updates can still fetch
write_stop_unit() {
  cat > "$STOP_UNIT" <<EOF_UNIT
[Unit]
Description=gryonixNexus updates at shutdown
Wants=network-online.target
After=network-online.target docker.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
ExecStop=$SELF stop-run
TimeoutStopSec=1h
[Install]
WantedBy=multi-user.target
EOF_UNIT
  systemctl daemon-reload
  systemctl enable --now "$STOP_UNIT_NAME" >/dev/null 2>&1
}

drop_stop_unit() {
  # Removed without stopping: a stop would run the updates right now
  systemctl disable "$STOP_UNIT_NAME" >/dev/null 2>&1 || true
  rm -f "$STOP_UNIT"
  systemctl daemon-reload
}

# Records one on/off choice
remember() {
  local key="$1" value="$2"
  case "$value" in on|off) ;; *) echo "unknown value: $value" >&2; exit 2 ;; esac
  install -d -m 755 "$(dirname "$CONF")"
  { grep -v "^$key=" "$CONF" 2>/dev/null || true; echo "$key=$value"; } > "$CONF.new"
  chmod 644 "$CONF.new"
  mv "$CONF.new" "$CONF"
}

at_start() {
  local what="${1:-}"
  case "$what" in system|apps) ;; *) echo "unknown part: $what" >&2; exit 2 ;; esac
  remember "$what" "${2:-}"
  if is_on system || is_on apps; then write_unit; else drop_unit; fi
  status
}

at_stop() {
  local what="${1:-}"
  case "$what" in system|apps) ;; *) echo "unknown part: $what" >&2; exit 2 ;; esac
  remember "${what}_stop" "${2:-}"
  if is_on system_stop || is_on apps_stop; then write_stop_unit; else drop_stop_unit; fi
  status
}

# The app's swap file: a new size, or none
set_swap() {
  local size="${1:-}" current free_gb
  if [ "$size" != off ]; then
    case "$size" in ''|*[!0-9]*) echo "unknown size: $size" >&2; exit 2 ;; esac
    if [ "$size" -lt 1 ] || [ "$size" -gt 256 ]; then echo "size out of range: $size" >&2; exit 2; fi
    current=$(( $(stat -c %s "$SWAPFILE" 2>/dev/null || echo 0) / 1073741824 ))
    free_gb=$(( $(df -B1 --output=avail / | tail -n 1 | tr -d ' ') / 1073741824 + current ))
    if [ "$size" -ge "$free_gb" ]; then echo "not enough disk: ${free_gb} GB free" >&2; exit 3; fi
  fi
  if swapon --show=NAME --noheadings | grep -qx "$SWAPFILE"; then swapoff "$SWAPFILE"; fi
  rm -f "$SWAPFILE"
  sed -i "\#^$SWAPFILE #d" /etc/fstab
  if [ "$size" != off ]; then
    fallocate -l "${size}G" "$SWAPFILE" 2>/dev/null || dd if=/dev/zero of="$SWAPFILE" bs=1M count="$((size * 1024))" status=none
    chmod 600 "$SWAPFILE"
    mkswap "$SWAPFILE" >/dev/null
    swapon "$SWAPFILE"
    echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab
  fi
  status
}

# The OnCalendar of every:<n>h@HH:MM or every:<n>d@HH:MM; never raw input
calendar_of() {
  local spec="${1#every:}"
  local every="${spec%@*}" at="${spec#*@}"
  local n="${every%[hd]}" unit="${every##*[0-9]}"
  case "$n" in ''|*[!0-9]*) return 1 ;; esac
  [ "$n" -ge 1 ] || return 1
  case "$at" in [0-2][0-9]:[0-5][0-9]) ;; *) return 1 ;; esac
  [ "${at%%:*}" -le 23 ] || return 1
  case "$unit" in
    h) if [ "$n" -ge 24 ]; then echo "*-*-* ${at}:00"; else echo "*-*-* 00/${n}:${at#*:}:00"; fi ;;
    d) if [ "$n" -le 1 ]; then echo "*-*-* ${at}:00"; else echo "*-*-01/${n} ${at}:00"; fi ;;
    *) return 1 ;;
  esac
}

write_timer() {
  cat > "$SCHEDULED" <<EOF_UNIT
[Unit]
Description=gryonixNexus scheduled system update
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
ExecStart=$SELF scheduled-run
TimeoutStartSec=2h
EOF_UNIT
  cat > "$TIMER" <<EOF_UNIT
[Unit]
Description=gryonixNexus scheduled system update
[Timer]
OnCalendar=$1
Persistent=true
RandomizedDelaySec=5m
[Install]
WantedBy=timers.target
EOF_UNIT
  systemctl daemon-reload
  systemctl enable --now "$TIMER_NAME" >/dev/null 2>&1
}

drop_timer() {
  systemctl disable --now "$TIMER_NAME" >/dev/null 2>&1 || true
  rm -f "$TIMER" "$SCHEDULED"
  systemctl daemon-reload
}

set_schedule() {
  local spec="${1:-off}" calendar=""
  if [ "$spec" != off ]; then
    case "$spec" in every:*) ;; *) echo "unsupported schedule: $spec" >&2; exit 2 ;; esac
    calendar=$(calendar_of "$spec") || { echo "invalid schedule: $spec" >&2; exit 2; }
    if command -v systemd-analyze >/dev/null 2>&1 && ! systemd-analyze calendar "$calendar" >/dev/null 2>&1; then
      echo "invalid schedule: $spec" >&2; exit 2
    fi
  fi
  install -d -m 755 "$(dirname "$SCHEDULE_CONF")"
  echo "schedule=$spec" > "$SCHEDULE_CONF.new"
  chmod 644 "$SCHEDULE_CONF.new"
  mv "$SCHEDULE_CONF.new" "$SCHEDULE_CONF"
  if [ "$spec" = off ]; then drop_timer; else write_timer "$calendar"; fi
  status
}

# The timer's run: the system only; the apps have their own schedule
scheduled_run() {
  : > "$LOG"
  chmod 644 "$LOG"
  local code=0
  upgrade >>"$LOG" 2>&1 || code=$?
  echo "$EXIT_MARK:$code" >>"$LOG"
}

# At start: the system first, then the apps the schedule names.
boot_run() {
  : > "$LOG"
  chmod 644 "$LOG"
  local code=0
  if is_on system; then upgrade >>"$LOG" 2>&1 || code=$?; fi
  if is_on apps && [ -x "$APPS" ]; then
    echo "## apps" >>"$LOG"
    "$APPS" run --scheduled >>"$LOG" 2>&1 || code=$?
  fi
  echo "$EXIT_MARK:$code" >>"$LOG"
}

# At shutdown: the same order, from the shutdown flags
stop_run() {
  : > "$LOG"
  chmod 644 "$LOG"
  local code=0
  if is_on system_stop; then upgrade >>"$LOG" 2>&1 || code=$?; fi
  if is_on apps_stop && [ -x "$APPS" ]; then
    echo "## apps" >>"$LOG"
    "$APPS" run --scheduled >>"$LOG" 2>&1 || code=$?
  fi
  echo "$EXIT_MARK:$code" >>"$LOG"
}

case "${1:-}" in
  status) status ;;
  start) start ;;
  at-start) shift; at_start "$@" ;;
  at-stop) shift; at_stop "$@" ;;
  swap) shift; set_swap "$@" ;;
  schedule) shift; set_schedule "$@" ;;
  scheduled-run) scheduled_run ;;
  run) upgrade ;;
  boot-run) boot_run ;;
  stop-run) stop_run ;;
  *) echo "unsupported action: ${1:-}" >&2; exit 2 ;;
esac

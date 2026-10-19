//! Port of `MetricsHistorySections` — `/opt/gryonixnexus-metrics-collector.sh` and its `gryonixnexus-metrics.service` unit

/// Where the collector script lives on disk.
pub const COLLECTOR_PATH: &str = "/opt/gryonixnexus-metrics-collector.sh";
pub const UNIT_PATH: &str = "/etc/systemd/system/gryonixnexus-metrics.service";
pub const UNIT_NAME: &str = "gryonixnexus-metrics";
/// Directory the collector writes its CSV buckets into
pub const DATA_DIRECTORY: &str = "/var/lib/gryonixnexus/metrics";
pub const STEP_SECONDS: u32 = 10;

pub const BUCKETS: &[(&str, u32, u32)] = &[
    ("10s", 10, 720),        // 2 hours
    ("1m", 60, 720),         // 12 hours
    ("10m", 600, 432),       // 3 days
    ("1h", 3_600, 336),      // 2 weeks
    ("1d", 86_400, 400),     // ~13 months
    ("1w", 604_800, 260),    // 5 years
];

pub const COLUMNS: &[&str] = &[
    "epoch", "cpu%", "memUsed", "memTotal", "diskUsed", "diskTotal", "netRx/s", "netTx/s", "ioRead/s", "ioWrite/s",
    "load1", "tempC",
];

pub fn collector_script() -> String {
    r#"#!/usr/bin/env bash
# Managed by gryonixNexus — samples host metrics every 10 seconds and keeps
# downsampled history buckets as CSV files under /var/lib/gryonixnexus/metrics.
# Columns: epoch,cpu%,memUsed,memTotal,diskUsed,diskTotal,netRx/s,netTx/s,
# ioRead/s,ioWrite/s,load1,tempC. Empty field = no data for that sample.
# Power: power-<bucket>.csv, columns epoch,watts,sensor, when a sensor exists.
# Disks: disks-<bucket>.csv, columns epoch,mount,used,total, one row per filesystem.
set -euo pipefail

DIR=/var/lib/gryonixnexus/metrics
STEP=10
install -d -m 755 /var/lib/gryonixnexus "$DIR"

cpu_ticks() { awk '$1=="cpu"{t=0; for(i=2;i<=9;i++) t+=$i; print t, $5+$6; exit}' /proc/stat; }
mem_bytes() { awk '/^MemTotal:/{t=$2*1024} /^MemAvailable:/{a=$2*1024} END{print t-a, t}' /proc/meminfo; }
disk_bytes() {
  { df -B1 --output=target,size,used -x tmpfs -x devtmpfs -x overlay 2>/dev/null || true; } \
    | awk 'NR>1 { if ($1=="/") {s=$2; u=$3; f=1} else if (!f && $2+0>s+0) {s=$2; u=$3} } END{print u+0, s+0}'
}
# Every real filesystem once: mount,used,total.
disk_rows() {
  { df -B1 --output=source,target,size,used -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs 2>/dev/null || true; } \
    | awk 'NR>1 && NF==4 && $3+0>0 && $2 !~ /,/ && $2 !~ /^\/(boot|snap|run|proc|sys|dev)(\/|$)/ && !seen[$1]++ {print $2","$4","$3}'
}
net_bytes() {
  awk -F: 'NF==2 {name=$1; gsub(/[ \t]/,"",name); if (name ~ /^(lo|veth.*|docker.*|br-.*|virbr.*|wg.*|awg.*|tun.*|tap.*|tailscale.*|zt.*|cali.*|flannel.*|cni.*|ifb.*|dummy.*)$/) next;
                  split($2,a," "); rx+=a[1]; tx+=a[9]} END{print rx+0, tx+0}' /proc/net/dev
}
io_bytes() {
  awk '$3 ~ /^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+)$/ \
         {r+=$6*512; w+=$10*512} END{print r+0, w+0}' /proc/diskstats
}
load_one() { awk '{print $1}' /proc/loadavg; }
temp_c() {
  { cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null || true; } \
    | awk '$1>0 && $1<150000 { if ($1>m) m=$1 } END{ if (m>0) printf "%.1f", m/1000 }'
}
rate() { awk -v c="$1" -v p="$2" -v s="$STEP" 'BEGIN{d=c-p; if (d<0) d=0; printf "%d", d/s}'; }

# Power sensors. Each prints watts, or nothing when absent.
POWERCAP=/sys/class/powercap
rapl_domains() {
  local d
  for d in "$POWERCAP"/intel-rapl:*; do
    case "${d##*/}" in *:*:*) continue ;; esac
    if [ -r "$d/energy_uj" ]; then echo "$d"; fi
  done
}
# Energy counter and its wrap range in microjoules; psys covers the platform.
rapl_uj() {
  local d name domains total=0 range=0
  domains=$(rapl_domains)
  [ -n "$domains" ] || return 0
  for d in $domains; do
    name=$(cat "$d/name" 2>/dev/null || true)
    if [ "$name" = psys ]; then domains=$d; break; fi
  done
  for d in $domains; do
    total=$(( total + $(cat "$d/energy_uj") ))
    range=$(( range + $(cat "$d/max_energy_range_uj" 2>/dev/null || echo 0) ))
  done
  echo "$total $range"
}
ipmi_w() {
  if [ ! -e /dev/ipmi0 ] || ! command -v ipmitool >/dev/null 2>&1; then return 0; fi
  timeout 5 ipmitool dcmi power reading 2>/dev/null \
    | awk -F: '/Instantaneous power reading/ {gsub(/[^0-9.]/, "", $2); if ($2+0>0) printf "%.1f", $2; exit}'
}
hwmon_w() {
  local f name
  for f in /sys/class/hwmon/hwmon*/power1_average /sys/class/hwmon/hwmon*/power1_input; do
    [ -r "$f" ] || continue
    name=$(cat "${f%/*}/name" 2>/dev/null || true)
    case "$name" in amdgpu|radeon|nouveau|i915|xe) continue ;; esac
    awk '$1>0 {printf "%.1f", $1/1000000}' "$f"
    return 0
  done
}
pi_w() {
  command -v vcgencmd >/dev/null 2>&1 || return 0
  vcgencmd pmic_read_adc 2>/dev/null | awk '
    { key=substr($1, 1, length($1)-2); v=$2; sub(/.*=/, "", v); sub(/[AV]$/, "", v) }
    $1 ~ /_A$/ {a[key]=v}
    $1 ~ /_V$/ {u[key]=v}
    END { for (k in a) if (k in u) w+=a[k]*u[k]; if (w>0) printf "%.1f", w }'
}
ups_w() {
  command -v upsc >/dev/null 2>&1 || return 0
  local ups
  ups=$(upsc -l 2>/dev/null | head -n 1)
  [ -n "$ups" ] || return 0
  upsc "$ups" 2>/dev/null | awk -F': ' '
    /^ups.realpower:/ {r=$2} /^ups.load:/ {l=$2} /^ups.realpower.nominal:/ {n=$2}
    END { if (r>0) printf "%.1f", r; else if (l>0 && n>0) printf "%.1f", l*n/100 }'
}


# Keep only the newest <max> rows of <file>.
trim() {
  local file=$1 max=$2 lines tmp
  [ -f "$file" ] || return 0
  lines=$(wc -l < "$file")
  if [ "$lines" -gt "$(( max + max / 10 ))" ]; then
    tmp=$(mktemp "$DIR/.trim.XXXXXX")
    tail -n "$max" "$file" > "$tmp"
    mv "$tmp" "$file"
    chmod 644 "$file"
  fi
}

# Average the source rows inside the just-closed <period> window and
# append one row to <target>. No-op while the window is still open, when
# it was already written, or when the source has no rows in it (gap).
aggregate() {
  local target=$1 source=$2 period=$3 keep=$4 now start last row
  [ -f "$source" ] || return 0
  now=$(date +%s)
  start=$(( now / period * period - period ))
  last=-1
  if [ -f "$target" ]; then
    last=$(tail -n 1 "$target" | cut -d, -f1)
    case "$last" in ''|*[!0-9]*) last=-1 ;; esac
  fi
  [ "$last" -lt "$start" ] || return 0
  row=$(awk -F, -v s="$start" -v e=$(( start + period )) '
    $1>=s && $1<e {
      n++
      if ($2!="") {c+=$2; cn++}
      mu+=$3; mt=$4; du+=$5; dt=$6
      if ($7!="") {rx+=$7; rxn++}
      if ($8!="") {tx+=$8; txn++}
      if ($9!="") {ir+=$9; irn++}
      if ($10!="") {iw+=$10; iwn++}
      l+=$11
      if ($12!="") {tp+=$12; tn++}
    }
    END {
      if (!n) exit 0
      printf "%d,", s
      if (cn) printf "%.1f", c/cn
      printf ",%d,%d,%d,%d,", mu/n, mt, du/n, dt
      if (rxn) printf "%d", rx/rxn
      printf ","
      if (txn) printf "%d", tx/txn
      printf ","
      if (irn) printf "%d", ir/irn
      printf ","
      if (iwn) printf "%d", iw/iwn
      printf ",%.2f,", l/n
      if (tn) printf "%.1f", tp/tn
      printf "\n"
    }' "$source")
  [ -n "$row" ] || return 0
  printf '%s\n' "$row" >> "$target"
  chmod 644 "$target"
  trim "$target" "$keep"
}


# Average watts inside the just-closed <period> window, same rules as above.
aggregate_power() {
  local target=$1 source=$2 period=$3 keep=$4 now start last row
  [ -f "$source" ] || return 0
  now=$(date +%s)
  start=$(( now / period * period - period ))
  last=-1
  if [ -f "$target" ]; then
    last=$(tail -n 1 "$target" | cut -d, -f1)
    case "$last" in ''|*[!0-9]*) last=-1 ;; esac
  fi
  [ "$last" -lt "$start" ] || return 0
  row=$(awk -F, -v s="$start" -v e=$(( start + period )) '
    $1>=s && $1<e && $2!="" {w+=$2; n++; src=$3}
    END { if (n) printf "%d,%.1f,%s\n", s, w/n, src }' "$source")
  [ -n "$row" ] || return 0
  printf '%s\n' "$row" >> "$target"
  chmod 644 "$target"
  trim "$target" "$keep"
}

# Average each filesystem inside the just-closed <period> window.
aggregate_disks() {
  local target=$1 source=$2 period=$3 keep=$4 now start last row
  [ -f "$source" ] || return 0
  now=$(date +%s)
  start=$(( now / period * period - period ))
  last=-1
  if [ -f "$target" ]; then
    last=$(tail -n 1 "$target" | cut -d, -f1)
    case "$last" in ''|*[!0-9]*) last=-1 ;; esac
  fi
  [ "$last" -lt "$start" ] || return 0
  row=$(awk -F, -v s="$start" -v e=$(( start + period )) '
    $1>=s && $1<e && NF==4 {u[$2]+=$3; t[$2]=$4; n[$2]++}
    END { for (m in n) printf "%d,%s,%d,%d\n", s, m, u[m]/n[m], t[m] }' "$source")
  [ -n "$row" ] || return 0
  printf '%s\n' "$row" >> "$target"
  chmod 644 "$target"
  trim "$target" $(( keep * 16 ))
}

prev_total=0 prev_idle=0 prev_rx=0 prev_tx=0 prev_ir=0 prev_iw=0 have_prev=0
prev_uj=0 prev_rapl_at=0 have_rapl=0

while :; do
  now=$(date +%s)
  read -r total idle < <(cpu_ticks)
  read -r mem_used mem_total < <(mem_bytes)
  read -r disk_used disk_total < <(disk_bytes)
  read -r rx tx < <(net_bytes)
  read -r io_r io_w < <(io_bytes)
  load=$(load_one)
  temp=$(temp_c)

  cpu="" rx_rate="" tx_rate="" ir_rate="" iw_rate=""
  if [ "$have_prev" -eq 1 ]; then
    cpu=$(awk -v t=$((total - prev_total)) -v i=$((idle - prev_idle)) \
      'BEGIN{ if (t>0) { p=(t-i)*100/t; if (p<0) p=0; if (p>100) p=100; printf "%.1f", p } }')
    rx_rate=$(rate "$rx" "$prev_rx")
    tx_rate=$(rate "$tx" "$prev_tx")
    ir_rate=$(rate "$io_r" "$prev_ir")
    iw_rate=$(rate "$io_w" "$prev_iw")
  fi

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$now" "$cpu" "$mem_used" "$mem_total" "$disk_used" "$disk_total" \
    "$rx_rate" "$tx_rate" "$ir_rate" "$iw_rate" "$load" "$temp" >> "$DIR/10s.csv"
  chmod 644 "$DIR/10s.csv"
  trim "$DIR/10s.csv" 720

  power="" psrc=""
  for probe in ipmi hwmon pi; do
    power=$("${probe}_w")
    if [ -n "$power" ]; then psrc=$probe; break; fi
  done
  rapl=$(rapl_uj)
  if [ -z "$power" ] && [ -n "$rapl" ] && [ "$have_rapl" -eq 1 ]; then
    power=$(awk -v c="${rapl% *}" -v p="$prev_uj" -v r="${rapl#* }" -v s=$(( now - prev_rapl_at )) \
      'BEGIN{d=c-p; if (d<0) d+=r; if (d>0 && s>0) printf "%.1f", d/1000000/s}')
    if [ -n "$power" ]; then psrc=rapl; fi
  fi
  if [ -n "$rapl" ]; then prev_uj=${rapl% *}; prev_rapl_at=$now; have_rapl=1; fi
  if [ -z "$power" ]; then
    power=$(ups_w)
    if [ -n "$power" ]; then psrc=ups; fi
  fi
  if [ -n "$power" ]; then
    printf '%s,%s,%s\n' "$now" "$power" "$psrc" >> "$DIR/power-10s.csv"
    chmod 644 "$DIR/power-10s.csv"
    trim "$DIR/power-10s.csv" 720
  fi

  disk_rows | awk -v t="$now" '{print t","$0}' >> "$DIR/disks-10s.csv"
  chmod 644 "$DIR/disks-10s.csv"
  trim "$DIR/disks-10s.csv" $(( 720 * 16 ))

  aggregate "$DIR/1m.csv"  "$DIR/10s.csv" 60      720
  aggregate "$DIR/10m.csv" "$DIR/1m.csv"  600     432
  aggregate "$DIR/1h.csv"  "$DIR/10m.csv" 3600    336
  aggregate "$DIR/1d.csv"  "$DIR/1h.csv"  86400   400
  aggregate "$DIR/1w.csv"  "$DIR/1d.csv"  604800  260
  aggregate_power "$DIR/power-1m.csv"  "$DIR/power-10s.csv" 60      720
  aggregate_power "$DIR/power-10m.csv" "$DIR/power-1m.csv"  600     432
  aggregate_power "$DIR/power-1h.csv"  "$DIR/power-10m.csv" 3600    336
  aggregate_power "$DIR/power-1d.csv"  "$DIR/power-1h.csv"  86400   400
  aggregate_power "$DIR/power-1w.csv"  "$DIR/power-1d.csv"  604800  260
  aggregate_disks "$DIR/disks-1m.csv"  "$DIR/disks-10s.csv" 60      720
  aggregate_disks "$DIR/disks-10m.csv" "$DIR/disks-1m.csv"  600     432
  aggregate_disks "$DIR/disks-1h.csv"  "$DIR/disks-10m.csv" 3600    336
  aggregate_disks "$DIR/disks-1d.csv"  "$DIR/disks-1h.csv"  86400   400
  aggregate_disks "$DIR/disks-1w.csv"  "$DIR/disks-1d.csv"  604800  260

  prev_total=$total prev_idle=$idle prev_rx=$rx prev_tx=$tx prev_ir=$io_r prev_iw=$io_w
  have_prev=1
  sleep "$STEP"
done"#
        .to_string()
}

/// The unit `UNIT_PATH` installs — byte-identical to `tests/fixtures/install/host/metrics_unit/*.txt`
pub fn unit() -> String {
    "[Unit]\nDescription=gryonixNexus metrics history collector\nAfter=local-fs.target\n\n[Service]\nExecStart=/opt/gryonixnexus-metrics-collector.sh\nRestart=always\nRestartSec=5\nNice=10\nIOSchedulingClass=idle\n\n[Install]\nWantedBy=multi-user.target"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(dir: &str, name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/host/{dir}/{name}.txt", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    /// Byte-for-byte parity against a real generated script
    #[test]
    fn collector_fixture_parity() {
        let expected = fixture("metrics", "A-adguard-access-en");
        assert_eq!(collector_script(), expected.trim_end_matches('\n'));
    }

    #[test]
    fn unit_fixture_parity() {
        let expected = fixture("metrics_unit", "A-adguard-access-en");
        assert_eq!(unit(), expected.trim_end_matches('\n'));
    }

    #[test]
    fn every_bucket_appears_with_its_period_and_retention() {
        let script = collector_script();
        let (name, period, keep) = BUCKETS[0];
        assert_eq!(name, "10s");
        assert_eq!(period, STEP_SECONDS);
        assert!(script.contains(&format!("trim \"$DIR/{name}.csv\" {keep}")));

        let sources = ["10s", "1m", "10m", "1h", "1d"];
        for (i, (name, period, keep)) in BUCKETS.iter().enumerate().skip(1) {
            let source = sources[i - 1];
            let line = format!("aggregate \"$DIR/{name}.csv\"");
            assert!(script.contains(&line), "no aggregate call writes {name}.csv:\n{script}");
            let call_start = script.find(&line).unwrap();
            let call_line = script[call_start..].lines().next().unwrap();
            assert!(
                call_line.contains(&format!("\"$DIR/{source}.csv\"")),
                "{name}'s aggregate call does not read from {source}.csv: {call_line}"
            );
            assert!(
                call_line.contains(&period.to_string()),
                "{name}'s aggregate call is missing its period {period}: {call_line}"
            );
            assert!(
                call_line.contains(&keep.to_string()),
                "{name}'s aggregate call is missing its retention {keep}: {call_line}"
            );
        }
    }

    #[test]
    fn there_are_exactly_six_buckets() {
        assert_eq!(BUCKETS.len(), 6);
        let script = collector_script();
        assert_eq!(script.matches("aggregate \"$DIR/").count(), 5, "expected 5 aggregate calls (6 buckets minus the raw one)");
    }

    #[test]
    fn the_column_count_matches_the_raw_row_printf() {
        assert_eq!(COLUMNS.len(), 12);
        let script = collector_script();
        let placeholders = "%s,".repeat(COLUMNS.len() - 1) + "%s\\n";
        assert!(
            script.contains(&format!("printf '{placeholders}' \\\n")),
            "raw-row printf does not have {} fields:\n{script}",
            COLUMNS.len()
        );
    }

    #[test]
    fn the_unit_restarts_forever_at_low_priority() {
        let u = unit();
        assert!(u.contains("Restart=always"));
        assert!(u.contains(&format!("ExecStart={COLLECTOR_PATH}")));
        assert!(u.contains("Nice=10"));
        assert!(u.contains("IOSchedulingClass=idle"));
    }

    #[test]
    fn unit_execstart_matches_the_collector_path() {
        assert!(unit().contains(&format!("ExecStart={COLLECTOR_PATH}\n")));
    }

    #[test]
    fn the_collector_writes_under_the_declared_data_directory() {
        assert!(collector_script().contains(&format!("DIR={DATA_DIRECTORY}\n")));
    }
}

//! Metrics history: the downsampled CSV buckets the on-host collector daemon writes under /var/lib/gryonixnexus/metrics

use std::path::{Path, PathBuf};

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::pb;

/// Where the collector keeps its buckets
const DEFAULT_DIR: &str = "/var/lib/gryonixnexus/metrics";

const BUCKETS: &[&str] = &["10s", "1m", "10m", "1h", "1d", "1w"];

const COLUMNS: usize = 12;

pub fn known_bucket(name: &str) -> Option<&'static str> {
    BUCKETS.iter().copied().find(|bucket| *bucket == name)
}

fn directory() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_METRICS_DIR").unwrap_or_else(|_| DEFAULT_DIR.to_string()))
}

/// The file one bucket lives in
fn bucket_path(dir: &Path, bucket: &'static str) -> PathBuf {
    dir.join(format!("{bucket}.csv"))
}

/// Read one bucket
pub fn read_bucket(bucket: &'static str) -> std::io::Result<Vec<pb::MetricsHistoryPoint>> {
    let dir = directory();
    let mut points = match std::fs::read_to_string(bucket_path(&dir, bucket)) {
        Ok(text) => parse(&text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(err),
    };
    if let Ok(text) = std::fs::read_to_string(dir.join(format!("power-{bucket}.csv"))) {
        attach_power(&mut points, &text);
    }
    Ok(points)
}

/// Joins `epoch,watts,sensor` rows onto the points of the same second.
fn attach_power(points: &mut [pb::MetricsHistoryPoint], text: &str) {
    let readings: std::collections::HashMap<i64, (f64, String)> = text
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(',');
            let seconds: i64 = fields.next()?.trim().parse().ok()?;
            let watts: f64 = fields.next()?.trim().parse().ok()?;
            let source = fields.next().unwrap_or("").trim().to_string();
            Some((seconds * 1000, (watts, source)))
        })
        .collect();
    for point in points.iter_mut() {
        if let Some((watts, source)) = readings.get(&point.at) {
            point.power_watts = Some(*watts);
            point.power_source = source.clone();
        }
    }
}

pub fn window(points: Vec<pb::MetricsHistoryPoint>, since: i64, limit: u32) -> Vec<pb::MetricsHistoryPoint> {
    let mut points: Vec<_> = if since > 0 {
        points.into_iter().filter(|p| p.at >= since).collect()
    } else {
        points
    };
    if limit > 0 && points.len() > limit as usize {
        points.drain(..points.len() - limit as usize);
    }
    points
}

/// The RPC
pub fn metrics_history(codec: Codec, req: pb::MetricsHistoryRequest) -> Resp {
    let Some(bucket) = known_bucket(&req.bucket) else {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            &format!(
                "unknown metrics bucket '{}' (expected one of {})",
                req.bucket.chars().take(32).collect::<String>(),
                BUCKETS.join(", ")
            ),
        );
    };
    let points = match read_bucket(bucket) {
        Ok(points) => points,
        Err(err) => {
            return connect_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                &format!("could not read the {bucket} history bucket: {err}"),
            )
        }
    };
    let response = pb::MetricsHistoryResponse {
        bucket: bucket.to_string(),
        points: window(points, req.since, req.limit),
    };
    codec.encode(&response).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

/// Parse a bucket file
fn parse(text: &str) -> Vec<pb::MetricsHistoryPoint> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<pb::MetricsHistoryPoint> {
    let fields: Vec<&str> = line.split(',').collect();
    if fields.len() != COLUMNS {
        return None;
    }
    let seconds: f64 = fields[0].trim().parse().ok()?;
    Some(pb::MetricsHistoryPoint {
        at: (seconds * 1000.0) as i64,
        cpu_percent: optional(fields[1]),
        mem_used_bytes: required_int(fields[2])?,
        mem_total_bytes: required_int(fields[3])?,
        disk_used_bytes: required_int(fields[4])?,
        disk_total_bytes: required_int(fields[5])?,
        net_received_per_second: optional(fields[6]),
        net_sent_per_second: optional(fields[7]),
        disk_read_per_second: optional(fields[8]),
        disk_written_per_second: optional(fields[9]),
        load1: fields[10].trim().parse().ok()?,
        temperature_celsius: optional(fields[11]),
        power_watts: None,
        power_source: String::new(),
    })
}

fn required_int(field: &str) -> Option<i64> {
    field.trim().parse().ok()
}

fn optional(field: &str) -> Option<f64> {
    let field = field.trim();
    if field.is_empty() {
        return None;
    }
    field.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
1754400000,12.5,1073741824,4294967296,5368709120,107374182400,1024.5,2048.5,100.5,200.5,0.42,41.2
1754400010,,1073741824,4294967296,5368709120,107374182400,,,,,0.10,
this is not a row
1754400020,7.5,1173741824,4294967296,5368709120,107374182400,10,20,30,40,1.00,39.0
";

    #[test]
    fn only_the_collectors_six_buckets_resolve() {
        for bucket in ["10s", "1m", "10m", "1h", "1d", "1w"] {
            assert_eq!(known_bucket(bucket), Some(bucket));
        }
        for hostile in ["10s.csv", "../../etc/shadow", "/etc/shadow", "10s/../1m", "30s", ""] {
            assert_eq!(known_bucket(hostile), None, "{hostile} must not resolve");
        }
    }

    #[test]
    fn the_path_is_built_from_the_table_not_from_the_request() {
        let dir = Path::new("/var/lib/gryonixnexus/metrics");
        for bucket in BUCKETS {
            let path = bucket_path(dir, bucket);
            assert_eq!(path.parent(), Some(dir));
            assert_eq!(path.file_name().unwrap().to_str().unwrap(), format!("{bucket}.csv"));
            assert!(!bucket.contains('/') && !bucket.contains('.'));
        }
    }

    #[test]
    fn parses_the_twelve_columns_in_the_collectors_order() {
        let points = parse(SAMPLE);
        assert_eq!(points.len(), 3, "the junk line is skipped, not fatal");
        let first = &points[0];
        assert_eq!(first.at, 1_754_400_000_000, "epoch seconds become Unix ms");
        assert_eq!(first.cpu_percent, Some(12.5));
        assert_eq!(first.mem_used_bytes, 1_073_741_824);
        assert_eq!(first.mem_total_bytes, 4_294_967_296);
        assert_eq!(first.disk_used_bytes, 5_368_709_120);
        assert_eq!(first.disk_total_bytes, 107_374_182_400);
        assert_eq!(first.net_received_per_second, Some(1024.5));
        assert_eq!(first.net_sent_per_second, Some(2048.5));
        assert_eq!(first.disk_read_per_second, Some(100.5));
        assert_eq!(first.disk_written_per_second, Some(200.5));
        assert_eq!(first.load1, 0.42);
        assert_eq!(first.temperature_celsius, Some(41.2));
    }

    #[test]
    fn an_empty_field_stays_absent_and_never_becomes_zero() {
        let point = &parse(SAMPLE)[1];
        assert_eq!(point.cpu_percent, None);
        assert_eq!(point.net_received_per_second, None);
        assert_eq!(point.net_sent_per_second, None);
        assert_eq!(point.disk_read_per_second, None);
        assert_eq!(point.disk_written_per_second, None);
        assert_eq!(point.temperature_celsius, None);
        // …while the gauges on the same row are real values.
        assert_eq!(point.mem_used_bytes, 1_073_741_824);
        assert_eq!(point.load1, 0.10);
    }

    #[test]
    fn a_row_with_the_wrong_column_count_is_skipped() {
        assert!(parse("1754400000,1,2,3\n").is_empty());
        let text = "1754400000,1,2,3,4,5,6,7,8,9,0.5,\n1754400010,1,2,3,4,5";
        assert_eq!(parse(text).len(), 1);
    }

    #[test]
    fn window_takes_the_newest_points_after_filtering_by_time() {
        let points = parse(SAMPLE);
        let recent = window(points.clone(), 0, 2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].at, 1_754_400_010_000);
        assert_eq!(recent[1].at, 1_754_400_020_000);

        let since = window(points.clone(), 1_754_400_010_000, 0);
        assert_eq!(since.len(), 2);
        assert_eq!(since[0].at, 1_754_400_010_000);

        let both = window(points, 1_754_400_010_000, 1);
        assert_eq!(both.len(), 1);
        assert_eq!(both[0].at, 1_754_400_020_000);
    }

    #[test]
    fn a_bucket_file_that_does_not_exist_is_empty_history_not_an_error() {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-history-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("GRYONIXNEXUSD_METRICS_DIR", &dir);
        assert_eq!(read_bucket("10s").unwrap().len(), 0);

        std::fs::write(bucket_path(&dir, "10s"), SAMPLE).unwrap();
        assert_eq!(read_bucket("10s").unwrap().len(), 3);
        std::env::remove_var("GRYONIXNEXUSD_METRICS_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn power_rows_join_their_own_second_and_leave_the_rest_alone() {
        let mut points = parse(SAMPLE);
        attach_power(&mut points, "1754400000,42.5,rapl\nnot a row\n1754400020,40.0,ipmi\n");
        assert_eq!(points[0].power_watts, Some(42.5));
        assert_eq!(points[0].power_source, "rapl");
        assert_eq!(points[1].power_watts, None);
        assert_eq!(points[2].power_source, "ipmi");
    }
}

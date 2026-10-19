//! Catalog order is ONE order, and the crate keeps three copies of it
use std::fs;

fn ordered_ids(source: &str, marker: &str) -> Vec<String> {
    let body = source
        .split_once(marker)
        .unwrap_or_else(|| panic!("{marker} must exist"))
        .1;
    let end = body.find("];").expect("the array must be closed");
    body[..end]
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("//") {
                return None;
            }
            let start = line.find('"')?;
            let rest = &line[start + 1..];
            let stop = rest.find('"')?;
            Some(rest[..stop].to_string())
        })
        .collect()
}

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("{path}: {err}"))
}

#[test]
fn restorable_order_follows_catalog_order() {
    let catalog = ordered_ids(&read("src/install/host/mod.rs"), "pub const CATALOG_ORDER");
    let restorable = ordered_ids(&read("src/install/host/restore.rs"), "const RESTORABLE_ORDER");
    assert!(!catalog.is_empty() && !restorable.is_empty());

    let filtered: Vec<&String> = catalog.iter().filter(|id| restorable.contains(id)).collect();
    let expected: Vec<&String> = restorable.iter().collect();
    assert_eq!(
        filtered, expected,
        "RESTORABLE_ORDER disagrees with CATALOG_ORDER — one shelf was reordered and only one list moved"
    );
}

#[test]
fn the_backup_wrappers_arms_follow_catalog_order() {
    let catalog = ordered_ids(&read("src/install/host/mod.rs"), "pub const CATALOG_ORDER");
    let source = read("src/install/host/backup_ctl.rs");

    let mut seen: Vec<(usize, String)> = Vec::new();
    for id in &catalog {
        if let Some(at) = source.find(&format!("if has(\"{id}\")")) {
            seen.push((at, id.clone()));
        }
    }
    let mut sorted = seen.clone();
    sorted.sort_by_key(|(at, _)| *at);
    assert_eq!(
        seen.iter().map(|(_, id)| id).collect::<Vec<_>>(),
        sorted.iter().map(|(_, id)| id).collect::<Vec<_>>(),
        "the backup wrapper emits services in a different order than the catalog — \
         its multi-service fixtures are the only other place this shows up"
    );
}

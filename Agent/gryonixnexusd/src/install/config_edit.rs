//! Edits single settings inside a service's own configuration file.

use std::path::Path;

/// Sets `key value` in a flat conf file
pub fn set_conf_line(text: &str, key: &str, value: &str) -> String {
    let wanted = format!("{key} {value}");
    let mut done = false;
    let mut lines: Vec<String> = text
        .lines()
        .map(|line| {
            let live = !line.trim_start().starts_with('#');
            if !done && live && line.split_whitespace().next() == Some(key) {
                done = true;
                wanted.clone()
            } else {
                line.to_string()
            }
        })
        .collect();
    if !done {
        lines.push(wanted);
    }
    lines.join("\n") + "\n"
}

/// Sets a top-level `KEY = value` line in Python
pub fn set_py_assign(text: &str, key: &str, value: &str) -> String {
    let wanted = format!("{key} = {value}");
    let mut done = false;
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let is_key = line.strip_prefix(key).is_some_and(|rest| rest.trim_start().starts_with('=') && !rest.trim_start().starts_with("=="));
        if !is_key {
            out.push(line.to_string());
        } else if !done {
            done = true;
            out.push(wanted.clone());
        }
    }
    if !done {
        out.push(wanted);
    }
    out.join("\n") + "\n"
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn is_live(line: &str) -> bool {
    let trimmed = line.trim();
    !trimmed.is_empty() && !trimmed.starts_with('#')
}

/// Sets a nested scalar in block-style YAML, adding missing keys
pub fn set_yaml_scalar(text: &str, path: &[&str], value: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut start = 0;
    let mut end = lines.len();
    let mut indent = 0;
    for (depth, key) in path.iter().enumerate() {
        let last = depth + 1 == path.len();
        let found = (start..end).find(|&at| {
            let line = &lines[at];
            is_live(line) && indent_of(line) == indent && line.trim_start().starts_with(&format!("{key}:"))
        });
        match found {
            Some(at) if last => {
                lines[at] = format!("{}{key}: {value}", " ".repeat(indent));
                return lines.join("\n") + "\n";
            }
            Some(at) => {
                let child = (at + 1..end).find(|&next| is_live(&lines[next]));
                let child_indent = child.map(|next| indent_of(&lines[next])).filter(|&n| n > indent).unwrap_or(indent + 2);
                let stop = (at + 1..end).find(|&next| is_live(&lines[next]) && indent_of(&lines[next]) <= indent).unwrap_or(end);
                start = at + 1;
                end = stop;
                indent = child_indent;
            }
            None => {
                let mut insert = end;
                while insert > start && !is_live(&lines[insert - 1]) {
                    insert -= 1;
                }
                let mut fresh = Vec::new();
                for (offset, name) in path[depth..].iter().enumerate() {
                    let pad = " ".repeat(indent + offset * 2);
                    if offset + 1 == path.len() - depth {
                        fresh.push(format!("{pad}{name}: {value}"));
                    } else {
                        fresh.push(format!("{pad}{name}:"));
                    }
                }
                lines.splice(insert..insert, fresh);
                return lines.join("\n") + "\n";
            }
        }
    }
    lines.join("\n") + "\n"
}

/// Rewrites a file through `change`, keeping a backup
pub fn rewrite(path: &Path, change: impl FnOnce(&str) -> String) -> std::io::Result<bool> {
    let before = std::fs::read_to_string(path)?;
    let after = change(&before);
    if after == before {
        return Ok(false);
    }
    let backup = path.with_extension(format!(
        "{}gnx-bak",
        path.extension().map(|ext| format!("{}.", ext.to_string_lossy())).unwrap_or_default()
    ));
    if !backup.exists() {
        std::fs::write(&backup, &before)?;
    }
    let mode = std::fs::metadata(path)?.permissions();
    let staging = path.with_extension("gnx-new");
    std::fs::write(&staging, &after)?;
    std::fs::set_permissions(&staging, mode)?;
    std::fs::rename(&staging, path)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_conf_line_is_replaced_in_place_or_appended() {
        assert_eq!(set_conf_line("a 1\nb 2\n", "a", "9"), "a 9\nb 2\n");
        assert_eq!(set_conf_line("a 1\n", "c", "3"), "a 1\nc 3\n");
        assert_eq!(set_conf_line("# a 1\n", "a", "2"), "# a 1\na 2\n");
    }

    #[test]
    fn a_python_assignment_is_replaced_deduplicated_or_appended() {
        let text = "SECRET_KEY = 'x'\nSITE_NAME = 'Old'\nSITE_NAME_EXTRA = 1\nSITE_NAME = 'Again'\n";
        assert_eq!(set_py_assign(text, "SITE_NAME", "'New'"), "SECRET_KEY = 'x'\nSITE_NAME = 'New'\nSITE_NAME_EXTRA = 1\n");
        assert_eq!(set_py_assign("A = 1\n", "B", "2"), "A = 1\nB = 2\n");
        assert_eq!(set_py_assign("  SITE_NAME = 1\n", "SITE_NAME", "2"), "  SITE_NAME = 1\nSITE_NAME = 2\n");
    }

    #[test]
    fn a_nested_yaml_scalar_is_replaced() {
        let text = "mqtt:\n  server: x\nfrontend:\n  enabled: true\n  port: 1\n";
        assert_eq!(set_yaml_scalar(text, &["frontend", "port"], "2"), "mqtt:\n  server: x\nfrontend:\n  enabled: true\n  port: 2\n");
    }

    #[test]
    fn missing_yaml_keys_are_added_under_their_parent() {
        let text = "mqtt:\n  server: x\n\nfrontend:\n  port: 1\n";
        let out = set_yaml_scalar(text, &["advanced", "log_level"], "debug");
        assert!(out.ends_with("advanced:\n  log_level: debug\n"));
        let out = set_yaml_scalar(text, &["mqtt", "keepalive"], "60");
        assert_eq!(out, "mqtt:\n  server: x\n  keepalive: 60\n\nfrontend:\n  port: 1\n");
    }

    #[test]
    fn a_same_named_key_in_another_block_is_left_alone() {
        let text = "a:\n  port: 1\nb:\n  port: 2\n";
        assert_eq!(set_yaml_scalar(text, &["b", "port"], "9"), "a:\n  port: 1\nb:\n  port: 9\n");
    }

    #[test]
    fn rewrite_keeps_a_backup_once() {
        let dir = std::env::temp_dir().join(format!("gnx-edit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("c.yaml");
        std::fs::write(&file, "a: 1\n").unwrap();
        assert!(rewrite(&file, |_| "a: 2\n".into()).unwrap());
        assert!(rewrite(&file, |_| "a: 3\n".into()).unwrap());
        assert!(!rewrite(&file, |text| text.to_string()).unwrap());
        assert_eq!(std::fs::read_to_string(dir.join("c.yaml.gnx-bak")).unwrap(), "a: 1\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

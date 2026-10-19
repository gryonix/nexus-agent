//! Port of `LockSections` — per-service locking shared by the backup and update wrappers

pub const DIRECTORY: &str = "/var/lib/gryonixnexus/locks";

/// `sysexits.h`'s `EX_TEMPFAIL`
pub const BUSY_EXIT_CODE: &str = "75";

/// The `gd_with_lock` helper, byte-identical to `LockSections.helper`
pub fn helper() -> String {
    format!(
        "GD_LOCK_BUSY={busy}\n\
         \n\
         gd_with_lock() {{\n\
         \x20 local id=\"$1\"\n\
         \x20 shift\n\
         \x20 install -d -m 700 '{dir}'\n\
         \x20 local fd\n\
         \x20 exec {{fd}}>\"{dir}/$id.lock\"\n\
         \x20 if ! flock -n \"$fd\"; then\n\
         \x20   echo \"$id: another backup or update for this service is already running, skipping\" >&2\n\
         \x20   return \"$GD_LOCK_BUSY\"\n\
         \x20 fi\n\
         \x20 \"$@\"\n\
         }}",
        busy = BUSY_EXIT_CODE,
        dir = DIRECTORY
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_helper_matches_the_real_generated_script_byte_for_byte() {
        let path = format!(
            "{}/tests/fixtures/install/host/lock-helper.txt",
            env!("CARGO_MANIFEST_DIR")
        );
        let expected = std::fs::read_to_string(&path).expect("fixture");
        assert_eq!(helper(), expected.trim_end_matches('\n'));
    }

    #[test]
    fn the_dynamic_descriptor_form_survives_the_port() {
        let helper = helper();
        assert!(helper.contains("exec {fd}>\"/var/lib/gryonixnexus/locks/$id.lock\""));
        assert!(helper.contains("flock -n \"$fd\""));
        assert!(!helper.contains("exec 9>"));
    }

    #[test]
    fn the_lock_is_never_blocking_and_reports_ex_tempfail() {
        assert_eq!(BUSY_EXIT_CODE, "75");
        assert!(helper().contains("GD_LOCK_BUSY=75"));
    }
}

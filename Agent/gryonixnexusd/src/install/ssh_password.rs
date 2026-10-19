//! Close SSH password login on a host this product provisions

use super::execute::EventSink;
use super::packages::{have_binary, run_outside_sandbox_from_file};

/// Where the drop-in lives
pub const DROP_IN_PATH: &str = "/etc/ssh/sshd_config.d/10-gryonixnexus-no-password.conf";

/// The staging name, which deliberately does NOT end in `.conf`
const STAGED_SUFFIX: &str = ".staged";

const VERDICT_PATH: &str = "/run/gryonixnexusd-sshd-password.verdict";

/// The drop-in itself
pub fn drop_in() -> String {
    "# Managed by gryonixNexus.\n\
     #\n\
     # Written only after the app key was proven present on the control user of\n\
     # this host. Numbered 10 so it is obtained BEFORE 50-cloud-init.conf: sshd\n\
     # keeps the FIRST value it sees for a keyword, and cloud images ship\n\
     # PasswordAuthentication yes in that file.\n\
     #\n\
     # Remove this file and reload ssh to take passwords again.\n\
     PasswordAuthentication no\n\
     KbdInteractiveAuthentication no\n"
        .to_string()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Closed,
    ClosedNotReloaded,
    ClosedUnverified,
    /// Nothing landed on disk
    NotWritten,
    NotEffective,
    /// Already exactly this file. Nothing written, nothing reloaded.
    AlreadyClosed,
    /// No proven key
    NoKey,
    InvalidConfig,
    /// No `sshd` on this host at all.
    NoSshd,
    PerAccountKept,
    AccountWithoutKey,
    Opened,
    AlreadyOpen,
    OpenedNotReloaded,
    OpenedNotEffective,
    OpenInvalidConfig,
}

impl Verdict {
    fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "closed" => Some(Self::Closed),
            "closed-not-reloaded" => Some(Self::ClosedNotReloaded),
            "closed-unverified" => Some(Self::ClosedUnverified),
            "not-written" => Some(Self::NotWritten),
            "not-effective" => Some(Self::NotEffective),
            "already-closed" => Some(Self::AlreadyClosed),
            "no-key" => Some(Self::NoKey),
            "invalid-config" => Some(Self::InvalidConfig),
            "no-sshd" => Some(Self::NoSshd),
            "per-account" => Some(Self::PerAccountKept),
            "account-without-key" => Some(Self::AccountWithoutKey),
            "opened" => Some(Self::Opened),
            "already-open" => Some(Self::AlreadyOpen),
            "opened-not-reloaded" => Some(Self::OpenedNotReloaded),
            "opened-not-effective" => Some(Self::OpenedNotEffective),
            "open-invalid-config" => Some(Self::OpenInvalidConfig),
            _ => None,
        }
    }

    /// The operator-facing sentence
    fn step(&self, user: &str) -> String {
        match self {
            Self::Closed => "SSH password login is closed on this host — key login only".to_string(),
            Self::ClosedNotReloaded => {
                "SSH password login is closed in the configuration, but sshd would not reload — \
                 it takes effect the next time sshd starts"
                    .to_string()
            }
            Self::ClosedUnverified => {
                "SSH password login is closed in the configuration, but sshd would not say what it \
                 resolved — check it by hand before relying on it"
                    .to_string()
            }
            Self::NotWritten => {
                "leaving SSH password login ON: the drop-in could not be written to this host at all"
                    .to_string()
            }
            Self::NotEffective => {
                "leaving SSH password login ON: sshd still accepts passwords with the drop-in in \
                 place, so something obtained earlier in its configuration wins — a cloud image's \
                 own sshd_config.d file is the usual one"
                    .to_string()
            }
            Self::AlreadyClosed => "SSH password login was already closed on this host".to_string(),
            Self::NoKey => format!(
                "leaving SSH password login ON: no login key is present for '{user}', and closing \
                 the door before the key is proven is how a host is lost"
            ),
            Self::InvalidConfig => {
                "leaving SSH password login ON: sshd rejected the configuration with the drop-in \
                 in place, so it was removed again"
                    .to_string()
            }
            Self::NoSshd => "not closing SSH password login: this host has no sshd".to_string(),
            Self::PerAccountKept => {
                "SSH password login stays as chosen per account on this host".to_string()
            }
            Self::AccountWithoutKey => {
                "leaving SSH password login ON: another login account on this host has no key, and \
                 closing passwords would lock it out — close it per account from the app instead"
                    .to_string()
            }
            Self::Opened => "SSH password login is open again on this host".to_string(),
            Self::AlreadyOpen => {
                "nothing to remove: this product has not closed SSH password login on this host"
                    .to_string()
            }
            Self::OpenedNotReloaded => {
                "SSH password login is open again in the configuration, but sshd would not reload \
                 — it takes effect the next time sshd starts"
                    .to_string()
            }
            Self::OpenedNotEffective => {
                "the drop-in is gone and sshd still refuses passwords: something else in this \
                 host's SSH configuration closes them, and it was not written by this app"
                    .to_string()
            }
            Self::OpenInvalidConfig => {
                "leaving SSH password login CLOSED: sshd rejected the configuration without the \
                 drop-in, so it was put back"
                    .to_string()
            }
        }
    }
}

/// Checks only the automatic close makes before touching sshd
const AUTOMATIC_GUARDS: &str = r#"# A per-account choice made in the app is never overwritten here.
if [ -f "$DROP_IN" ] && grep -q '^Match User' "$DROP_IN"; then say per-account; exit 0; fi
# Every other login account must have a key before passwords close.
getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)$/ { print $1 ":" $6 }' |
while IFS=: read -r ACCOUNT ACCOUNT_HOME; do
  [ "$ACCOUNT" = "$CONTROL_USER" ] && continue
  [ -s "$ACCOUNT_HOME/.ssh/authorized_keys" ] || { echo "$ACCOUNT"; break; }
done > "$VERDICT.keyless"
if [ -s "$VERDICT.keyless" ]; then rm -f "$VERDICT.keyless"; say account-without-key; exit 0; fi
rm -f "$VERDICT.keyless"

"#;

/// The script that does the work, outside this process's sandbox
fn script(control_user: &str, app_public_key: &str, automatic: bool) -> String {
    let verdict = verdict_path();
    let guards = if automatic { AUTOMATIC_GUARDS } else { "" };
    format!(
        "set -u\n\
         VERDICT='{verdict}'\n\
         DROP_IN='{DROP_IN_PATH}'\n\
         STAGED=\"$DROP_IN{STAGED_SUFFIX}\"\n\
         CONTROL_USER='{control_user}'\n\
         APP_KEY='{app_public_key}'\n\
         rm -f \"$VERDICT\"\n\
         say() {{ printf '%s\\n' \"$1\" > \"$VERDICT\"; }}\n\
         \n\
         if ! command -v sshd >/dev/null 2>&1; then say no-sshd; exit 0; fi\n\
         \n\
         # The guard asks for THE APP KEY, not for any key: an existing-user\n\
         # install leaves the account untouched, so this file can be full of\n\
         # keys that belong to somebody else while the app itself signs in with\n\
         # a password. A home directory that does not resolve, a missing file\n\
         # and a file without our line are one answer: no proven way back in.\n\
         HOME_DIR=\"$(getent passwd \"$CONTROL_USER\" | cut -d: -f6)\"\n\
         if [ -z \"$HOME_DIR\" ]; then say no-key; exit 0; fi\n\
         KEYS=\"$HOME_DIR/.ssh/authorized_keys\"\n\
         if [ ! -s \"$KEYS\" ]; then say no-key; exit 0; fi\n\
         if ! grep -qxF \"$APP_KEY\" \"$KEYS\"; then say no-key; exit 0; fi\n\
         \n\
         {guards}\
         install -d -m 755 /etc/ssh/sshd_config.d\n\
         cat > \"$STAGED\" <<'GRYONIXNEXUS_SSHD_DROP_IN'\n\
         {body}\
         GRYONIXNEXUS_SSHD_DROP_IN\n\
         chmod 644 \"$STAGED\"\n\
         if [ -f \"$DROP_IN\" ] && cmp -s \"$STAGED\" \"$DROP_IN\"; then\n\
         \x20 rm -f \"$STAGED\"\n\
         \x20 say already-closed\n\
         \x20 exit 0\n\
         fi\n\
         mv \"$STAGED\" \"$DROP_IN\"\n\
         \n\
         # **Did the file actually land?** There is no `set -e` here on purpose\n\
         # (every exit has to leave a verdict), which means a failed install -d,\n\
         # a full disk or a read-only /etc would fall straight through to the\n\
         # test below — and that test PASSES when nothing was added, because the\n\
         # configuration is then exactly what it was. Without this line the\n\
         # agent reports the door closed on a host where it is wide open.\n\
         if [ ! -f \"$DROP_IN\" ]; then\n\
         \x20 rm -f \"$STAGED\"\n\
         \x20 say not-written\n\
         \x20 exit 0\n\
         fi\n\
         \n\
         # Tested with the file IN PLACE, because an include is the only way\n\
         # sshd ever sees it — and removed again on rejection, so a host that\n\
         # cannot parse this keeps the behaviour it had instead of losing sshd.\n\
         if ! sshd -t; then\n\
         \x20 rm -f \"$DROP_IN\"\n\
         \x20 say invalid-config\n\
         \x20 exit 0\n\
         fi\n\
         if ! systemctl reload ssh 2>/dev/null && ! systemctl reload sshd 2>/dev/null; then\n\
         \x20 say closed-not-reloaded\n\
         \x20 exit 0\n\
         fi\n\
         \n\
         # **The only proof that survives contact with a real host: ask sshd.**\n\
         # A file on disk says nothing about the MERGED configuration, and this\n\
         # is the one place the numbering can be checked against a machine\n\
         # rather than against a unit test: a cloud image that ships\n\
         # 50-cloud-init.conf with PasswordAuthentication yes would leave every\n\
         # step above successful and the door open. sshd -T prints what sshd\n\
         # itself resolved.\n\
         EFFECTIVE=\"$(sshd -T 2>/dev/null | tr 'A-Z' 'a-z')\"\n\
         if [ -z \"$EFFECTIVE\" ]; then say closed-unverified; exit 0; fi\n\
         case \"$EFFECTIVE\" in\n\
         \x20 *\"passwordauthentication no\"*) ;;\n\
         \x20 *) say not-effective; exit 0 ;;\n\
         esac\n\
         case \"$EFFECTIVE\" in\n\
         \x20 *\"kbdinteractiveauthentication no\"*) ;;\n\
         \x20 *) say not-effective; exit 0 ;;\n\
         esac\n\
         say closed\n",
        body = drop_in(),
    )
}

pub(super) async fn close_password_login(
    control_user: Option<&str>,
    app_public_key: Option<&str>,
    sink: &EventSink,
) {
    let (user, key) = match subject(control_user, app_public_key) {
        Ok(pair) => pair,
        Err(why) => {
            let _ = sink.step(why).await;
            return;
        }
    };
    if !have_binary("systemd-run") {
        let _ = sink
            .step("not closing SSH password login: this build can only reach sshd through systemd-run")
            .await;
        return;
    }

    let _ = std::fs::remove_file(verdict_path());
    if let Err(why) =
        run_outside_sandbox_from_file(&script(user, key, true), "closing SSH password login", sink).await
    {
        let _ = sink.step(&format!("could not close SSH password login: {why}")).await;
        return;
    }

    let verdict = std::fs::read_to_string(verdict_path()).ok().and_then(|text| Verdict::parse(&text));
    let _ = std::fs::remove_file(verdict_path());
    match verdict {
        Some(verdict) => {
            let _ = sink.step(verdict.step(user)).await;
        }
        None => {
            let _ = sink
                .step("could not tell whether SSH password login was closed — assume it is still open")
                .await;
        }
    }
}

fn subject<'a>(
    control_user: Option<&'a str>,
    app_public_key: Option<&'a str>,
) -> Result<(&'a str, &'a str), &'static str> {
    let user = control_user
        .map(str::trim)
        .filter(|user| !user.is_empty())
        .ok_or("not closing SSH password login: this host has no gryonixNexus control user whose key could be proven")?;
    let key = app_public_key
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .ok_or("not closing SSH password login: this host does not know which key the app signs in with")?;
    if key.contains('\'') || key.contains('\n') {
        return Err("not closing SSH password login: this host's recorded app key is not a single line");
    }
    Ok((user, key))
}

/// Overridable for tests, the same technique `systemd_run_bin` uses
fn verdict_path() -> String {
    std::env::var("GRYONIXNEXUSD_SSHD_VERDICT_PATH").unwrap_or_else(|_| VERDICT_PATH.to_string())
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct State {
    /// sshd accepts passwords
    pub password_open: Option<bool>,
    pub app_key_present: bool,
    /// This product's drop-in is on disk
    pub drop_in_present: bool,
    pub sshd_present: bool,
    pub login_user: String,
}

/// Where the probe leaves its line
fn probe_verdict_path() -> String {
    format!("{}.probe", verdict_path())
}

fn resolve_login_user(login_user: &str) -> Option<String> {
    let named = login_user.trim();
    if !named.is_empty() {
        return Some(named.to_string());
    }
    super::execute::existing_control_user()
}

fn shell_safe(value: &str) -> bool {
    !value.contains('\'') && !value.contains('\n') && !value.contains('\r')
}

/// The read, outside the sandbox
fn probe_script(login_user: &str, app_public_key: &str) -> String {
    let verdict = probe_verdict_path();
    format!(
        "set -u\n\
         VERDICT='{verdict}'\n\
         DROP_IN='{DROP_IN_PATH}'\n\
         LOGIN_USER='{login_user}'\n\
         APP_KEY='{app_public_key}'\n\
         OPEN=unknown\n\
         KEY=no\n\
         DROPIN=no\n\
         SSHD=no\n\
         # Present means the HOST-WIDE close is on disk. A file scoped to a\n\
         # `Match User` block makes no claim about the host, and reading it as\n\
         # one is what told the owner cloud-init was outranking a file that was\n\
         # never about the host in the first place.\n\
         if [ -f \"$DROP_IN\" ] && ! grep -q '^Match User' \"$DROP_IN\"; then DROPIN=yes; fi\n\
         \n\
         # The same grep the guard uses, for the same reason: an adopted host's\n\
         # authorized_keys is usually full of the OWNER's keys, and \"some key is\n\
         # present\" is the answer that would lock the app out.\n\
         if [ -n \"$APP_KEY\" ]; then\n\
         \x20 HOME_DIR=\"$(getent passwd \"$LOGIN_USER\" | cut -d: -f6)\"\n\
         \x20 if [ -n \"$HOME_DIR\" ] && [ -s \"$HOME_DIR/.ssh/authorized_keys\" ]; then\n\
         \x20   if grep -qxF \"$APP_KEY\" \"$HOME_DIR/.ssh/authorized_keys\"; then KEY=yes; fi\n\
         \x20 fi\n\
         fi\n\
         \n\
         # `sshd -T` and nothing else. Reading the files would mean\n\
         # reimplementing sshd's own first-value-wins merge over a glob, which\n\
         # is the exact thing this module was written after getting wrong.\n\
         if command -v sshd >/dev/null 2>&1; then\n\
         \x20 SSHD=yes\n\
         \x20 EFFECTIVE=\"$(sshd -T 2>/dev/null | tr 'A-Z' 'a-z')\"\n\
         \x20 if [ -n \"$EFFECTIVE\" ]; then\n\
         \x20   OPEN=yes\n\
         \x20   case \"$EFFECTIVE\" in\n\
         \x20     *\"passwordauthentication no\"*)\n\
         \x20       case \"$EFFECTIVE\" in\n\
         \x20         *\"kbdinteractiveauthentication no\"*) OPEN=no ;;\n\
         \x20       esac\n\
         \x20       ;;\n\
         \x20   esac\n\
         \x20 fi\n\
         fi\n\
         \n\
         # **Host-wide is not the only way this door gets shut.** The app can\n\
         # close passwords account by account, and sshd resolves a `Match User`\n\
         # block only when it is asked about a user, so the bare `sshd -T`\n\
         # above prints yes on a host where every account that could sign in is\n\
         # key-only. Asking per account answers the question the card draws:\n\
         # can anybody still get in with a password. An account sshd would not\n\
         # answer about counts as open, never as closed.\n\
         if [ \"$OPEN\" = yes ]; then\n\
         \x20 ANY_OPEN=no\n\
         \x20 ASKED=no\n\
         \x20 while IFS=: read -r NAME _ ACCOUNT_UID _ _ HOME_DIR SHELL_PATH; do\n\
         \x20   case \"$SHELL_PATH\" in *nologin|*/false|'') continue ;; esac\n\
         \x20   case \"$ACCOUNT_UID\" in ''|*[!0-9]*) continue ;; esac\n\
         \x20   if [ \"$ACCOUNT_UID\" -ne 0 ] && [ \"$ACCOUNT_UID\" -lt 1000 ]; then continue; fi\n\
         \x20   PER=\"$(sshd -T -C user=\"$NAME\",host=localhost,addr=127.0.0.1 2>/dev/null | tr 'A-Z' 'a-z')\"\n\
         \x20   if [ -z \"$PER\" ]; then ANY_OPEN=yes; break; fi\n\
         \x20   ASKED=yes\n\
         \x20   case \"$PER\" in\n\
         \x20     *\"passwordauthentication no\"*)\n\
         \x20       case \"$PER\" in\n\
         \x20         *\"kbdinteractiveauthentication no\"*) ;;\n\
         \x20         *) ANY_OPEN=yes; break ;;\n\
         \x20       esac\n\
         \x20       ;;\n\
         \x20     *) ANY_OPEN=yes; break ;;\n\
         \x20   esac\n\
         \x20 done < /etc/passwd\n\
         \x20 if [ \"$ASKED\" = yes ] && [ \"$ANY_OPEN\" = no ]; then OPEN=no; fi\n\
         fi\n\
         printf 'open=%s key=%s dropin=%s sshd=%s\\n' \"$OPEN\" \"$KEY\" \"$DROPIN\" \"$SSHD\" > \"$VERDICT\"\n",
    )
}

/// Read the probe's line back
fn parse_state(text: &str) -> State {
    let mut state = State::default();
    for field in text.split_whitespace() {
        match field.split_once('=') {
            Some(("open", "yes")) => state.password_open = Some(true),
            Some(("open", "no")) => state.password_open = Some(false),
            Some(("key", "yes")) => state.app_key_present = true,
            Some(("dropin", "yes")) => state.drop_in_present = true,
            Some(("sshd", "yes")) => state.sshd_present = true,
            _ => {}
        }
    }
    state
}

/// Taking this product's drop-in back off, outside the sandbox
fn open_script() -> String {
    let verdict = verdict_path();
    format!(
        "set -u\n\
         VERDICT='{verdict}'\n\
         DROP_IN='{DROP_IN_PATH}'\n\
         BACKUP=\"$DROP_IN{STAGED_SUFFIX}\"\n\
         rm -f \"$VERDICT\"\n\
         say() {{ printf '%s\\n' \"$1\" > \"$VERDICT\"; }}\n\
         \n\
         if ! command -v sshd >/dev/null 2>&1; then say no-sshd; exit 0; fi\n\
         if [ ! -f \"$DROP_IN\" ]; then say already-open; exit 0; fi\n\
         \n\
         # Moved aside under the staging name, which the include glob does not\n\
         # match, so the file is out of the configuration and still on disk for\n\
         # the one path that has to put it back.\n\
         mv \"$DROP_IN\" \"$BACKUP\"\n\
         if [ -f \"$DROP_IN\" ]; then say not-written; exit 0; fi\n\
         if ! sshd -t; then\n\
         \x20 mv \"$BACKUP\" \"$DROP_IN\"\n\
         \x20 say open-invalid-config\n\
         \x20 exit 0\n\
         fi\n\
         rm -f \"$BACKUP\"\n\
         if ! systemctl reload ssh 2>/dev/null && ! systemctl reload sshd 2>/dev/null; then\n\
         \x20 say opened-not-reloaded\n\
         \x20 exit 0\n\
         fi\n\
         EFFECTIVE=\"$(sshd -T 2>/dev/null | tr 'A-Z' 'a-z')\"\n\
         if [ -z \"$EFFECTIVE\" ]; then say opened; exit 0; fi\n\
         case \"$EFFECTIVE\" in\n\
         \x20 *\"passwordauthentication yes\"*) say opened ;;\n\
         \x20 *) say opened-not-effective ;;\n\
         esac\n",
    )
}

async fn run_and_read(script: &str, what: &str, verdict: &str) -> Result<String, String> {
    if !have_binary("systemd-run") {
        return Err("this build can only reach sshd through systemd-run, and this host has none"
            .to_string());
    }
    let _ = std::fs::remove_file(verdict);
    let sink = EventSink::detached();
    run_outside_sandbox_from_file(script, what, &sink).await?;
    let text = std::fs::read_to_string(verdict).map_err(|err| {
        format!("{what} left no answer behind, so what the host now accepts is unknown: {err}")
    })?;
    let _ = std::fs::remove_file(verdict);
    Ok(text)
}

pub async fn read_state(login_user: &str, app_public_key: &str) -> Result<State, String> {
    let user = resolve_login_user(login_user).ok_or_else(|| {
        "no account to ask about: name the account the app signs in with — this host has no \
         gryonixNexus control user to fall back to"
            .to_string()
    })?;
    if !shell_safe(&user) || !shell_safe(app_public_key) {
        return Err("the account name or the key is not a single plain line".to_string());
    }
    let text =
        run_and_read(&probe_script(&user, app_public_key), "reading the SSH login policy", &probe_verdict_path())
            .await?;
    let mut state = parse_state(&text);
    state.login_user = user;
    Ok(state)
}

pub async fn close_password_login_now(
    login_user: &str,
    app_public_key: &str,
) -> Result<Verdict, String> {
    let user = resolve_login_user(login_user).ok_or_else(|| {
        "not closing SSH password login: name the account the app signs in with — this host has \
         no gryonixNexus control user to fall back to"
            .to_string()
    })?;
    let (user, key) = subject(Some(user.as_str()), Some(app_public_key))
        .map_err(str::to_string)
        .map(|(user, key)| (user.to_string(), key.to_string()))?;
    if !shell_safe(&user) {
        return Err("not closing SSH password login: that account name is not a single plain line"
            .to_string());
    }
    let text = run_and_read(&script(&user, &key, false), "closing SSH password login", &verdict_path()).await?;
    Verdict::parse(&text).ok_or_else(|| {
        "could not tell whether SSH password login was closed — assume it is still open".to_string()
    })
}

pub async fn open_password_login_now() -> Result<Verdict, String> {
    let text = run_and_read(&open_script(), "opening SSH password login", &verdict_path()).await?;
    Verdict::parse(&text).ok_or_else(|| {
        "could not tell whether SSH password login was opened — assume it is still closed"
            .to_string()
    })
}

pub fn verdict_sentence(verdict: &Verdict, login_user: &str) -> String {
    verdict.step(login_user)
}

/// One account and what sshd resolves for it
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct UserAccess {
    pub name: String,
    /// sshd accepts passwords FOR THIS ACCOUNT
    pub password_open: Option<bool>,
    /// The account carries at least one key of its own
    pub has_keys: bool,
    /// The app's key is on this account
    pub app_key_present: bool,
}

/// Who the drop-in is written about
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum KeyOnly {
    Everyone,
    /// These accounts only, through a `Match User` block
    Accounts(Vec<String>),
}

/// The drop-in for a scope
pub fn drop_in_for(scope: &KeyOnly) -> String {
    let names = match scope {
        KeyOnly::Everyone => return drop_in(),
        KeyOnly::Accounts(names) if names.is_empty() => return drop_in(),
        KeyOnly::Accounts(names) => names.join(","),
    };
    format!(
        "# Managed by gryonixNexus.\n\
         #\n\
         # Key login only for the accounts named below. Numbered 10 so it is\n\
         # obtained BEFORE 50-cloud-init.conf: sshd keeps the FIRST value it\n\
         # sees for a keyword, and cloud images ship PasswordAuthentication yes\n\
         # in that file.\n\
         #\n\
         # The block ends with Match all, because everything after a Match line\n\
         # belongs to it — including the rest of sshd_config, which is read\n\
         # after this file is included.\n\
         #\n\
         # Remove this file and reload ssh to take passwords again.\n\
         Match User {names}\n\
         \x20 PasswordAuthentication no\n\
         \x20 KbdInteractiveAuthentication no\n\
         Match all\n"
    )
}

/// Where the account probe leaves its lines
fn users_verdict_path() -> String {
    format!("{}.users", verdict_path())
}

fn users_script(app_public_key: &str) -> String {
    let verdict = users_verdict_path();
    format!(
        "set -u\n\
         VERDICT='{verdict}'\n\
         APP_KEY='{app_public_key}'\n\
         : > \"$VERDICT\"\n\
         HAS_SSHD=no\n\
         command -v sshd >/dev/null 2>&1 && HAS_SSHD=yes\n\
         while IFS=: read -r NAME _ ACCOUNT_UID _ _ HOME_DIR SHELL_PATH; do\n\
         \x20 case \"$SHELL_PATH\" in *nologin|*/false|'') continue ;; esac\n\
         \x20 case \"$ACCOUNT_UID\" in ''|*[!0-9]*) continue ;; esac\n\
         \x20 if [ \"$ACCOUNT_UID\" -ne 0 ] && [ \"$ACCOUNT_UID\" -lt 1000 ]; then continue; fi\n\
         \x20 KEYS=no\n\
         \x20 APPKEY=no\n\
         \x20 OPEN=unknown\n\
         \x20 if [ -n \"$HOME_DIR\" ] && [ -s \"$HOME_DIR/.ssh/authorized_keys\" ]; then\n\
         \x20   KEYS=yes\n\
         \x20   if [ -n \"$APP_KEY\" ] && grep -qxF \"$APP_KEY\" \"$HOME_DIR/.ssh/authorized_keys\"; then\n\
         \x20     APPKEY=yes\n\
         \x20   fi\n\
         \x20 fi\n\
         \x20 if [ \"$HAS_SSHD\" = yes ]; then\n\
         \x20   EFFECTIVE=\"$(sshd -T -C user=\"$NAME\",host=localhost,addr=127.0.0.1 2>/dev/null | tr 'A-Z' 'a-z')\"\n\
         \x20   if [ -n \"$EFFECTIVE\" ]; then\n\
         \x20     OPEN=yes\n\
         \x20     case \"$EFFECTIVE\" in\n\
         \x20       *\"passwordauthentication no\"*)\n\
         \x20         case \"$EFFECTIVE\" in\n\
         \x20           *\"kbdinteractiveauthentication no\"*) OPEN=no ;;\n\
         \x20         esac\n\
         \x20         ;;\n\
         \x20     esac\n\
         \x20   fi\n\
         \x20 fi\n\
         \x20 printf 'user=%s open=%s keys=%s appkey=%s\\n' \"$NAME\" \"$OPEN\" \"$KEYS\" \"$APPKEY\" >> \"$VERDICT\"\n\
         done < /etc/passwd\n",
    )
}

fn parse_users(text: &str) -> Vec<UserAccess> {
    let mut users = Vec::new();
    for line in text.lines() {
        let mut user = UserAccess::default();
        for field in line.split_whitespace() {
            match field.split_once('=') {
                Some(("user", name)) => user.name = name.to_string(),
                Some(("open", "yes")) => user.password_open = Some(true),
                Some(("open", "no")) => user.password_open = Some(false),
                Some(("keys", "yes")) => user.has_keys = true,
                Some(("appkey", "yes")) => user.app_key_present = true,
                _ => {}
            }
        }
        if !user.name.is_empty() {
            users.push(user);
        }
    }
    users
}

pub async fn list_users(app_public_key: &str) -> Result<Vec<UserAccess>, String> {
    if !shell_safe(app_public_key) {
        return Err("the key is not a single plain line".to_string());
    }
    let text = run_and_read(
        &users_script(app_public_key),
        "reading the SSH accounts",
        &users_verdict_path(),
    )
    .await?;
    Ok(parse_users(&text))
}

/// The close script for a named set of accounts
fn named_script(names: &[String], login_user: &str, app_public_key: &str) -> String {
    let verdict = verdict_path();
    let body = drop_in_for(&KeyOnly::Accounts(names.to_vec()));
    let list = names.join(" ");
    format!(
        "set -u\n\
         VERDICT='{verdict}'\n\
         DROP_IN='{DROP_IN_PATH}'\n\
         STAGED=\"$DROP_IN{STAGED_SUFFIX}\"\n\
         LOGIN_USER='{login_user}'\n\
         APP_KEY='{app_public_key}'\n\
         NAMES='{list}'\n\
         rm -f \"$VERDICT\"\n\
         say() {{ printf '%s\\n' \"$1\" > \"$VERDICT\"; }}\n\
         \n\
         if ! command -v sshd >/dev/null 2>&1; then say no-sshd; exit 0; fi\n\
         \n\
         for NAME in $NAMES; do\n\
         \x20 HOME_DIR=\"$(getent passwd \"$NAME\" | cut -d: -f6)\"\n\
         \x20 if [ -z \"$HOME_DIR\" ]; then say no-key; exit 0; fi\n\
         \x20 KEYS=\"$HOME_DIR/.ssh/authorized_keys\"\n\
         \x20 if [ ! -s \"$KEYS\" ]; then say no-key; exit 0; fi\n\
         \x20 if [ \"$NAME\" = \"$LOGIN_USER\" ] && [ -n \"$APP_KEY\" ]; then\n\
         \x20   if ! grep -qxF \"$APP_KEY\" \"$KEYS\"; then say no-key; exit 0; fi\n\
         \x20 fi\n\
         done\n\
         \n\
         install -d -m 755 /etc/ssh/sshd_config.d\n\
         cat > \"$STAGED\" <<'GRYONIXNEXUS_SSHD_DROP_IN'\n\
         {body}\
         GRYONIXNEXUS_SSHD_DROP_IN\n\
         chmod 644 \"$STAGED\"\n\
         if [ -f \"$DROP_IN\" ] && cmp -s \"$STAGED\" \"$DROP_IN\"; then\n\
         \x20 rm -f \"$STAGED\"\n\
         \x20 say already-closed\n\
         \x20 exit 0\n\
         fi\n\
         # The old file is kept until the new one is proven: a rejected\n\
         # configuration must leave the host with what it was running.\n\
         if [ -f \"$DROP_IN\" ]; then cp \"$DROP_IN\" \"$DROP_IN.previous\"; fi\n\
         mv \"$STAGED\" \"$DROP_IN\"\n\
         if [ ! -f \"$DROP_IN\" ]; then\n\
         \x20 rm -f \"$STAGED\"\n\
         \x20 say not-written\n\
         \x20 exit 0\n\
         fi\n\
         if ! sshd -t; then\n\
         \x20 if [ -f \"$DROP_IN.previous\" ]; then mv \"$DROP_IN.previous\" \"$DROP_IN\"; else rm -f \"$DROP_IN\"; fi\n\
         \x20 say invalid-config\n\
         \x20 exit 0\n\
         fi\n\
         rm -f \"$DROP_IN.previous\"\n\
         if ! systemctl reload ssh 2>/dev/null && ! systemctl reload sshd 2>/dev/null; then\n\
         \x20 say closed-not-reloaded\n\
         \x20 exit 0\n\
         fi\n\
         \n\
         # Asked per account, because a Match block is resolved by sshd and by\n\
         # nothing else — the whole reason this file is shaped the way it is.\n\
         for NAME in $NAMES; do\n\
         \x20 EFFECTIVE=\"$(sshd -T -C user=\"$NAME\",host=localhost,addr=127.0.0.1 2>/dev/null | tr 'A-Z' 'a-z')\"\n\
         \x20 if [ -z \"$EFFECTIVE\" ]; then say closed-unverified; exit 0; fi\n\
         \x20 case \"$EFFECTIVE\" in\n\
         \x20   *\"passwordauthentication no\"*) ;;\n\
         \x20   *) say not-effective; exit 0 ;;\n\
         \x20 esac\n\
         \x20 case \"$EFFECTIVE\" in\n\
         \x20   *\"kbdinteractiveauthentication no\"*) ;;\n\
         \x20   *) say not-effective; exit 0 ;;\n\
         \x20 esac\n\
         done\n\
         say closed\n",
    )
}

/// Close password login for a scope, on demand
pub async fn set_key_only_now(
    scope: &KeyOnly,
    login_user: &str,
    app_public_key: &str,
) -> Result<Verdict, String> {
    let names = match scope {
        KeyOnly::Everyone => return close_password_login_now(login_user, app_public_key).await,
        KeyOnly::Accounts(names) if names.is_empty() => return open_password_login_now().await,
        KeyOnly::Accounts(names) => names.clone(),
    };
    let user = resolve_login_user(login_user).unwrap_or_default();
    if !shell_safe(&user) || !shell_safe(app_public_key) {
        return Err("the account name or the key is not a single plain line".to_string());
    }
    for name in &names {
        if !shell_safe(name) || name.contains(' ') || name.contains(',') {
            return Err(format!("'{name}' is not a plain account name"));
        }
    }
    let text = run_and_read(
        &named_script(&names, &user, app_public_key),
        "closing SSH password login for the named accounts",
        &verdict_path(),
    )
    .await?;
    Verdict::parse(&text).ok_or_else(|| {
        "could not tell whether SSH password login was closed — assume it is still open".to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake gryonixnexus-app";

    #[test]
    fn the_drop_in_outranks_cloud_inits() {
        let name = DROP_IN_PATH.rsplit('/').next().expect("a file name");
        assert!(name < "50-cloud-init.conf", "{name} is obtained after cloud-init's drop-in");
        assert!(name < "60-gryonixnexus-tunnel.conf", "{name}");
        assert!(DROP_IN_PATH.starts_with("/etc/ssh/sshd_config.d/"), "{DROP_IN_PATH}");
        assert!(DROP_IN_PATH.ends_with(".conf"), "{DROP_IN_PATH} would not be included at all");
    }

    #[test]
    fn both_password_keywords_are_closed() {
        let text = drop_in();
        let directives: Vec<&str> =
            text.lines().filter(|line| !line.trim_start().starts_with('#')).filter(|line| !line.trim().is_empty()).collect();
        assert!(directives.contains(&"PasswordAuthentication no"), "{text}");
        assert!(directives.contains(&"KbdInteractiveAuthentication no"), "{text}");
        assert_eq!(directives.len(), 2, "nothing else belongs in this file: {text}");
    }

    #[test]
    fn the_drop_in_body_carries_nothing_a_shell_literal_could_not_hold() {
        let text = drop_in();
        assert!(!text.contains('\''), "an apostrophe ends the other route's literal: {text}");
        assert!(text.is_ascii(), "the other route embeds this verbatim: {text}");
    }

    #[test]
    fn the_staged_file_is_invisible_to_the_include_glob() {
        assert!(!STAGED_SUFFIX.is_empty());
        assert!(
            !format!("{DROP_IN_PATH}{STAGED_SUFFIX}").ends_with(".conf"),
            "the staged file would be included while it is being written"
        );
    }

    /// The rejection path must UNDO itself
    #[test]
    fn a_rejected_configuration_removes_the_drop_in_again() {
        let text = script("gryonixnexus", FAKE_KEY, true);
        let test_at = text.find("if ! sshd -t; then").expect("the merged config is tested");
        let removal_at = text[test_at..].find("rm -f \"$DROP_IN\"").expect("a rejection removes the file");
        let verdict_at = text[test_at..].find("say invalid-config").expect("a rejection is reported");
        assert!(removal_at < verdict_at, "the file is removed before the verdict is written:\n{text}");
    }

    #[test]
    fn a_write_that_did_not_land_is_not_reported_as_closed() {
        let text = script("gryonixnexus", FAKE_KEY, true);
        let landed = text
            .find("if [ ! -f \"$DROP_IN\" ]; then")
            .expect("nothing checks that the drop-in reached the disk");
        let tested = text.find("if ! sshd -t; then").expect("the merged config is tested");
        assert!(landed < tested, "the existence check runs after the test that cannot fail:\n{text}");
        assert!(text[landed..tested].contains("say not-written"), "{text}");
    }

    #[test]
    fn the_host_itself_is_asked_whether_passwords_are_still_taken() {
        let text = script("gryonixnexus", FAKE_KEY, true);
        let reload = text.find("systemctl reload").expect("sshd is reloaded");
        let asked = text.find("sshd -T").expect("sshd is never asked what it resolved");
        assert!(reload < asked, "asked before the reload, so it reads the OLD answer:\n{text}");
        assert!(text[asked..].contains("passwordauthentication no"), "{text}");
        assert!(text[asked..].contains("kbdinteractiveauthentication no"), "{text}");
        assert!(text.contains("tr 'A-Z' 'a-z'"), "{text}");
        assert!(text[asked..].contains("say closed-unverified"), "{text}");
    }

    #[test]
    fn sshd_is_reloaded_and_never_restarted() {
        let text = script("gryonixnexus", FAKE_KEY, true);
        assert!(text.contains("systemctl reload ssh"), "{text}");
        assert!(text.contains("systemctl reload sshd"), "{text}");
        assert!(!text.contains("systemctl restart ssh"), "a restart drops the install's own session:\n{text}");
        assert!(!text.contains("reboot"), "{text}");
    }

    /// The reload only ever happens AFTER the test passes
    #[test]
    fn nothing_is_reloaded_before_the_configuration_is_tested() {
        let text = script("gryonixnexus", FAKE_KEY, true);
        let test_at = text.find("sshd -t").expect("the config is tested");
        let reload_at = text.find("systemctl reload").expect("sshd is reloaded");
        assert!(test_at < reload_at, "{text}");
    }

    #[test]
    fn every_way_of_having_no_key_refuses_to_write_the_drop_in() {
        let text = script("gryonixnexus", FAKE_KEY, true);
        let write_at = text.find("mv \"$STAGED\" \"$DROP_IN\"").expect("the drop-in is installed");
        for guard in [
            "if [ -z \"$HOME_DIR\" ]; then say no-key; exit 0; fi",
            "if [ ! -s \"$KEYS\" ]; then say no-key; exit 0; fi",
            "if ! grep -qxF \"$APP_KEY\" \"$KEYS\"; then say no-key; exit 0; fi",
        ] {
            let at = text.find(guard).unwrap_or_else(|| panic!("missing guard {guard}:\n{text}"));
            assert!(at < write_at, "this guard runs after the file is written:\n{guard}");
        }
    }

    #[test]
    fn the_guard_looks_for_the_apps_own_key_and_not_merely_a_key() {
        let text = script("gryonixnexus", FAKE_KEY, true);
        assert!(text.contains(&format!("APP_KEY='{FAKE_KEY}'")), "{text}");
        assert!(text.contains("grep -qxF \"$APP_KEY\" \"$KEYS\""), "{text}");
        assert!(!text.contains("grep -q \"$APP_KEY\""), "a substring match is not a key: {text}");
    }

    #[test]
    fn the_control_user_is_quoted_into_the_script() {
        assert!(script("admin", FAKE_KEY, true).contains("CONTROL_USER='admin'"), "{}", script("admin", FAKE_KEY, true));
    }

    #[test]
    fn the_script_writes_exactly_the_published_drop_in() {
        let text = script("gryonixnexus", FAKE_KEY, true);
        assert!(text.contains(&drop_in()), "{text}");
        assert!(text.contains("<<'GRYONIXNEXUS_SSHD_DROP_IN'"), "{text}");
    }

    #[test]
    fn every_verdict_the_script_can_write_is_understood() {
        let text = script("gryonixnexus", FAKE_KEY, true);
        let mut said = Vec::new();
        let mut rest = text.as_str();
        while let Some(at) = rest.find("say ") {
            let tail = &rest[at + 4..];
            let end = tail.find(|c: char| !(c.is_ascii_alphanumeric() || c == '-')).unwrap_or(tail.len());
            if end > 0 {
                said.push(tail[..end].to_string());
            }
            rest = &tail[end.max(1)..];
        }
        // `say() {` itself is not a verdict; every other occurrence is.
        said.retain(|word| word != "say");
        assert!(!said.is_empty(), "{text}");
        for word in &said {
            assert!(Verdict::parse(word).is_some(), "the agent would not understand the verdict {word:?}");
        }
        for word in [
            "closed",
            "closed-not-reloaded",
            "closed-unverified",
            "already-closed",
            "no-key",
            "invalid-config",
            "no-sshd",
            "not-written",
            "not-effective",
        ] {
            assert!(said.iter().any(|said| said == word), "the script never writes {word:?}");
        }
    }

    /// An unknown word is NOT rounded up to success
    #[test]
    fn an_unrecognised_verdict_is_not_a_success() {
        assert_eq!(Verdict::parse("probably fine"), None);
        assert_eq!(Verdict::parse(""), None);
        assert_eq!(Verdict::parse(" closed \n"), Some(Verdict::Closed));
    }

    /// Every verdict has to say what the host accepts now
    #[test]
    fn the_verdicts_that_leave_passwords_on_say_which_they_are() {
        for verdict in [Verdict::NoKey, Verdict::InvalidConfig, Verdict::NotWritten, Verdict::NotEffective] {
            let line = verdict.step("gryonixnexus");
            assert!(line.contains("leaving SSH password login ON"), "{line}");
        }
        assert!(Verdict::NoKey.step("bot").contains("'bot'"), "the account is named: {}", Verdict::NoKey.step("bot"));
    }

    #[test]
    fn nothing_is_closed_without_both_a_control_user_and_a_known_app_key() {
        assert!(subject(None, Some(FAKE_KEY)).is_err(), "no control user");
        assert!(subject(Some(""), Some(FAKE_KEY)).is_err(), "blank control user");
        assert!(subject(Some("gryonixnexus"), None).is_err(), "no known app key");
        assert!(subject(Some("gryonixnexus"), Some("   ")).is_err(), "blank app key");
        assert_eq!(subject(Some("gryonixnexus"), Some(FAKE_KEY)), Ok(("gryonixnexus", FAKE_KEY)));
    }

    #[test]
    fn a_key_that_could_break_out_of_the_shell_literal_is_refused() {
        assert!(subject(Some("gryonixnexus"), Some("ssh-ed25519 AAA' ; rm -rf / #")).is_err());
        assert!(subject(Some("gryonixnexus"), Some("ssh-ed25519 AAA\nssh-rsa BBB")).is_err());
    }

    #[test]
    fn the_script_parses_under_plain_sh() {
        let out = std::process::Command::new("sh")
            .arg("-n")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.take().expect("a stdin pipe").write_all(script("gryonixnexus", FAKE_KEY, true).as_bytes())?;
                child.wait_with_output()
            })
            .expect("sh runs");
        assert!(
            out.status.success(),
            "sh -n rejected the script: {}\n{}",
            String::from_utf8_lossy(&out.stderr),
            script("gryonixnexus", FAKE_KEY, true)
        );
    }
}

#[cfg(test)]
mod execution {
    use std::path::{Path, PathBuf};

    const FAKE_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake gryonixnexus-app";

    /// One run of the real script against a sandbox.
    struct Run {
        root: PathBuf,
        verdict: String,
        drop_in: PathBuf,
    }

    fn sandbox(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sshd-close-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).expect("a sandbox");
        dir
    }

    fn stub(root: &Path, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = root.join("bin").join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("a stub");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("a stub");
    }

    fn with_keys(root: &Path, keys: Option<&str>) {
        let home = root.join("home/gryonixnexus");
        std::fs::create_dir_all(home.join(".ssh")).expect("a home");
        stub(root, "getent", &format!("printf 'gryonixnexus:x:1000:1000::{}:/bin/bash\\n'", home.display()));
        match keys {
            Some(text) => std::fs::write(home.join(".ssh/authorized_keys"), text).expect("keys"),
            None => {
                let _ = std::fs::remove_file(home.join(".ssh/authorized_keys"));
            }
        }
    }

    fn run(root: &Path) -> Run {
        let drop_in = root.join("etc/ssh/sshd_config.d/10-gryonixnexus-no-password.conf");
        let verdict_path = root.join("verdict");
        let text = super::script("gryonixnexus", FAKE_KEY, true)
            .replace("/etc/ssh/sshd_config.d", &root.join("etc/ssh/sshd_config.d").display().to_string())
            .replace(super::VERDICT_PATH, &verdict_path.display().to_string());

        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&text)
            .env("PATH", format!("{}:/usr/bin:/bin", root.join("bin").display()))
            .output()
            .expect("sh runs");
        assert!(
            out.status.success(),
            "the script exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        Run {
            root: root.to_path_buf(),
            verdict: std::fs::read_to_string(&verdict_path).unwrap_or_default().trim().to_string(),
            drop_in,
        }
    }

    impl Run {
        fn wrote_drop_in(&self) -> bool {
            self.drop_in.exists()
        }
        fn staged_left_behind(&self) -> bool {
            self.root.join("etc/ssh/sshd_config.d").read_dir().map(|entries| {
                entries.flatten().any(|e| e.file_name().to_string_lossy().ends_with(".staged"))
            }).unwrap_or(false)
        }
    }

    fn healthy(root: &Path) {
        stub(root, "sshd", "case \"$1\" in\n  -t) exit 0 ;;\n  -T) printf 'passwordauthentication no\\nkbdinteractiveauthentication no\\n' ;;\nesac");
        stub(root, "systemctl", "exit 0");
    }

    #[test]
    fn a_host_with_the_app_key_ends_up_closed_and_says_so() {
        let root = sandbox("closed");
        with_keys(&root, Some(&format!("# a comment\n\n{FAKE_KEY}\n")));
        healthy(&root);
        let run = run(&root);
        assert_eq!(run.verdict, "closed");
        assert!(run.wrote_drop_in(), "nothing was written");
        assert_eq!(std::fs::read_to_string(&run.drop_in).unwrap(), super::drop_in());
        assert!(!run.staged_left_behind(), "the staged file was left in the include directory");
    }

    #[test]
    fn a_second_run_is_a_no_op() {
        let root = sandbox("idempotent");
        with_keys(&root, Some(FAKE_KEY));
        healthy(&root);
        assert_eq!(run(&root).verdict, "closed");
        stub(&root, "systemctl", "exit 1");
        let again = run(&root);
        assert_eq!(again.verdict, "already-closed");
        assert!(again.wrote_drop_in());
    }

    #[test]
    fn another_account_without_a_key_keeps_passwords_open() {
        let root = sandbox("keyless-neighbour");
        with_keys(&root, Some(FAKE_KEY));
        let home = root.join("home/gryonixnexus");
        let other = root.join("home/admin");
        std::fs::create_dir_all(&other).expect("a home");
        stub(
            &root,
            "getent",
            &format!(
                "if [ -n \"$2\" ]; then printf 'gryonixnexus:x:1000:1000::{h}:/bin/bash\\n'; \
                 else printf 'gryonixnexus:x:1000:1000::{h}:/bin/bash\\nadmin:x:1001:1001::{o}:/bin/bash\\n'; fi",
                h = home.display(),
                o = other.display()
            ),
        );
        healthy(&root);
        let run = run(&root);
        assert_eq!(run.verdict, "account-without-key");
        assert!(!run.wrote_drop_in(), "passwords were closed around an account with no key");
    }

    #[test]
    fn a_per_account_choice_is_left_as_it_is() {
        let root = sandbox("per-account");
        with_keys(&root, Some(FAKE_KEY));
        healthy(&root);
        let dir = root.join("etc/ssh/sshd_config.d");
        std::fs::create_dir_all(&dir).expect("an include dir");
        let chosen = "Match User admin\n  PasswordAuthentication no\n";
        std::fs::write(dir.join("10-gryonixnexus-no-password.conf"), chosen).expect("a drop-in");
        let run = run(&root);
        assert_eq!(run.verdict, "per-account");
        assert_eq!(std::fs::read_to_string(&run.drop_in).unwrap(), chosen);
    }

    #[test]
    fn no_proven_key_writes_nothing_at_all() {
        for (name, keys) in [
            ("missing", None),
            ("empty", Some("")),
            ("comments-only", Some("# nothing but a comment\n\n")),
            ("somebody-elses-key", Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsomeoneElse owner\n")),
            ("prefix-of-ours", Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake\n")),
        ] {
            let root = sandbox(&format!("nokey-{name}"));
            with_keys(&root, keys);
            healthy(&root);
            let run = run(&root);
            assert_eq!(run.verdict, "no-key", "{name}");
            assert!(!run.wrote_drop_in(), "{name}: a file was written with no proven key");
        }
    }

    #[test]
    fn a_rejected_configuration_is_undone_on_the_disk() {
        let root = sandbox("rejected");
        with_keys(&root, Some(FAKE_KEY));
        stub(&root, "sshd", "case \"$1\" in\n  -t) exit 1 ;;\nesac");
        stub(&root, "systemctl", "echo 'reloaded a rejected configuration' >&2; exit 0");
        let run = run(&root);
        assert_eq!(run.verdict, "invalid-config");
        assert!(!run.wrote_drop_in(), "the host keeps a configuration sshd will not parse");
    }

    #[test]
    fn a_write_that_cannot_happen_is_reported_as_open() {
        let root = sandbox("unwritable");
        with_keys(&root, Some(FAKE_KEY));
        healthy(&root);
        std::fs::create_dir_all(root.join("etc/ssh")).expect("etc/ssh");
        std::fs::write(root.join("etc/ssh/sshd_config.d"), "not a directory").expect("a blocker");
        let run = run(&root);
        assert_eq!(run.verdict, "not-written", "a failed write was reported as success");
    }

    #[test]
    fn a_drop_in_that_is_outranked_is_reported_as_open() {
        let root = sandbox("outranked");
        with_keys(&root, Some(FAKE_KEY));
        stub(&root, "sshd", "case \"$1\" in\n  -t) exit 0 ;;\n  -T) printf 'passwordauthentication yes\\nkbdinteractiveauthentication no\\n' ;;\nesac");
        stub(&root, "systemctl", "exit 0");
        let run = run(&root);
        assert_eq!(run.verdict, "not-effective");
        assert!(run.wrote_drop_in());
    }

    #[test]
    fn keyboard_interactive_left_open_is_reported_as_open() {
        let root = sandbox("kbd");
        with_keys(&root, Some(FAKE_KEY));
        stub(&root, "sshd", "case \"$1\" in\n  -t) exit 0 ;;\n  -T) printf 'passwordauthentication no\\nkbdinteractiveauthentication yes\\n' ;;\nesac");
        stub(&root, "systemctl", "exit 0");
        assert_eq!(run(&root).verdict, "not-effective");
    }

    #[test]
    fn a_host_without_sshd_says_so() {
        let root = sandbox("no-sshd");
        with_keys(&root, Some(FAKE_KEY));
        stub(&root, "systemctl", "exit 0");
        let run = run(&root);
        assert_eq!(run.verdict, "no-sshd");
        assert!(!run.wrote_drop_in());
    }

    #[test]
    fn a_daemon_that_will_not_reload_is_not_called_closed() {
        let root = sandbox("no-reload");
        with_keys(&root, Some(FAKE_KEY));
        stub(&root, "sshd", "case \"$1\" in\n  -t) exit 0 ;;\n  -T) printf 'passwordauthentication no\\nkbdinteractiveauthentication no\\n' ;;\nesac");
        stub(&root, "systemctl", "exit 1");
        let run = run(&root);
        assert_eq!(run.verdict, "closed-not-reloaded");
        assert!(run.wrote_drop_in());
    }
}

#[cfg(test)]
mod on_demand {
    use std::path::{Path, PathBuf};

    const FAKE_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake gryonixnexus-app";

    fn sandbox(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sshd-ondemand-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).expect("a sandbox");
        std::fs::create_dir_all(dir.join("etc/ssh/sshd_config.d")).expect("a sandbox");
        dir
    }

    fn stub(root: &Path, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = root.join("bin").join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("a stub");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("a stub");
    }

    fn with_keys(root: &Path, keys: Option<&str>) {
        let home = root.join("home/owner");
        std::fs::create_dir_all(home.join(".ssh")).expect("a home");
        stub(root, "getent", &format!("printf 'owner:x:1000:1000::{}:/bin/bash\\n'", home.display()));
        match keys {
            Some(text) => std::fs::write(home.join(".ssh/authorized_keys"), text).expect("keys"),
            None => {
                let _ = std::fs::remove_file(home.join(".ssh/authorized_keys"));
            }
        }
    }

    fn sshd_saying(root: &Path, effective: Option<&str>) {
        let answer = match effective {
            Some(text) => format!("printf '{text}'"),
            None => String::new(),
        };
        stub(root, "sshd", &format!("case \"$1\" in\n  -t) exit 0 ;;\n  -T) {answer} ;;\nesac"));
    }

    fn sshd_saying_per_account(root: &Path, host: &str, per_account: &str) {
        stub(
            root,
            "sshd",
            &format!(
                "case \"$1\" in\n\
                 \x20 -t) exit 0 ;;\n\
                 \x20 -T)\n\
                 \x20   case \"$*\" in\n\
                 \x20     *\"-C \"*) printf '{per_account}' ;;\n\
                 \x20     *) printf '{host}' ;;\n\
                 \x20   esac\n\
                 \x20   ;;\n\
                 esac"
            ),
        );
    }

    fn drop_in_path(root: &Path) -> PathBuf {
        root.join("etc/ssh/sshd_config.d/10-gryonixnexus-no-password.conf")
    }

    fn run(root: &Path, text: &str, verdict_name: &str) -> String {
        let verdict = root.join(verdict_name);
        let script = text
            .replace("/etc/ssh/sshd_config.d", &root.join("etc/ssh/sshd_config.d").display().to_string())
            .replace(&super::probe_verdict_path(), &verdict.display().to_string())
            .replace(super::VERDICT_PATH, &verdict.display().to_string());
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            .env("PATH", format!("{}:/usr/bin:/bin", root.join("bin").display()))
            .output()
            .expect("sh runs");
        assert!(
            out.status.success(),
            "the script exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        std::fs::read_to_string(&verdict).unwrap_or_default().trim().to_string()
    }

    fn probe(root: &Path) -> super::State {
        let line = run(root, &super::probe_script("owner", FAKE_KEY), "probe");
        super::parse_state(&line)
    }

    fn open(root: &Path) -> String {
        run(root, &super::open_script(), "verdict")
    }

    // ── The read ────────────────────────────────────────────────────────────

    #[test]
    fn an_open_host_without_the_app_key_reads_as_both() {
        let root = sandbox("open-nokey");
        with_keys(&root, Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsomeoneElse owner\n"));
        sshd_saying(&root, Some("passwordauthentication yes\\nkbdinteractiveauthentication yes\\n"));
        let state = probe(&root);
        assert_eq!(state.password_open, Some(true));
        assert!(!state.app_key_present, "somebody else's key was taken for ours");
        assert!(!state.drop_in_present);
        assert!(state.sshd_present);
    }

    #[test]
    fn the_key_is_found_only_when_the_whole_line_is_there() {
        for (name, keys, expected) in [
            ("exactly-ours", Some(format!("# a comment\n\n{FAKE_KEY}\n")), true),
            ("prefix-of-ours", Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake\n".to_string()), false),
            ("empty", Some(String::new()), false),
            ("missing", None, false),
        ] {
            let root = sandbox(&format!("key-{name}"));
            with_keys(&root, keys.as_deref());
            sshd_saying(&root, Some("passwordauthentication yes\\n"));
            assert_eq!(probe(&root).app_key_present, expected, "{name}");
        }
    }

    #[test]
    fn a_drop_in_that_is_outranked_reads_as_present_and_still_open() {
        let root = sandbox("outranked");
        with_keys(&root, Some(FAKE_KEY));
        std::fs::write(drop_in_path(&root), super::drop_in()).expect("a drop-in");
        sshd_saying(&root, Some("passwordauthentication yes\\nkbdinteractiveauthentication no\\n"));
        let state = probe(&root);
        assert!(state.drop_in_present);
        assert_eq!(state.password_open, Some(true), "the file was believed over sshd");
    }

    #[test]
    fn keyboard_interactive_alone_still_reads_as_open() {
        let root = sandbox("kbd");
        with_keys(&root, Some(FAKE_KEY));
        sshd_saying(&root, Some("passwordauthentication no\\nkbdinteractiveauthentication yes\\n"));
        assert_eq!(probe(&root).password_open, Some(true));
    }

    /// A closed host, read back as closed.
    #[test]
    fn a_closed_host_reads_as_closed() {
        let root = sandbox("closed");
        with_keys(&root, Some(FAKE_KEY));
        std::fs::write(drop_in_path(&root), super::drop_in()).expect("a drop-in");
        sshd_saying(&root, Some("passwordauthentication no\\nkbdinteractiveauthentication no\\n"));
        let state = probe(&root);
        assert_eq!(state.password_open, Some(false));
        assert!(state.app_key_present);
        assert!(state.drop_in_present);
    }

    #[test]
    fn a_host_closed_account_by_account_reads_as_closed() {
        let root = sandbox("per-account-closed");
        with_keys(&root, Some(FAKE_KEY));
        std::fs::write(
            drop_in_path(&root),
            super::drop_in_for(&super::KeyOnly::Accounts(vec!["owner".into()])),
        )
        .expect("a drop-in");
        sshd_saying_per_account(
            &root,
            "passwordauthentication yes\\nkbdinteractiveauthentication yes\\n",
            "passwordauthentication no\\nkbdinteractiveauthentication no\\n",
        );
        let state = probe(&root);
        assert_eq!(state.password_open, Some(false));
        assert!(!state.drop_in_present, "a Match-scoped file was read as the host-wide close");
    }

    #[test]
    fn an_account_that_still_takes_passwords_keeps_the_host_open() {
        let root = sandbox("per-account-open");
        with_keys(&root, Some(FAKE_KEY));
        sshd_saying_per_account(
            &root,
            "passwordauthentication yes\\n",
            "passwordauthentication yes\\n",
        );
        assert_eq!(probe(&root).password_open, Some(true));
    }

    #[test]
    fn an_account_sshd_will_not_answer_about_leaves_the_host_open() {
        let root = sandbox("per-account-silent");
        with_keys(&root, Some(FAKE_KEY));
        sshd_saying_per_account(&root, "passwordauthentication yes\\n", "");
        assert_eq!(probe(&root).password_open, Some(true));
    }

    #[test]
    fn an_sshd_that_says_nothing_leaves_the_reading_unknown() {
        let root = sandbox("silent");
        with_keys(&root, Some(FAKE_KEY));
        sshd_saying(&root, None);
        let state = probe(&root);
        assert_eq!(state.password_open, None);
        assert!(state.sshd_present);
    }

    #[test]
    fn a_host_without_sshd_reads_as_neither() {
        let root = sandbox("no-sshd");
        with_keys(&root, Some(FAKE_KEY));
        let state = probe(&root);
        assert!(!state.sshd_present);
        assert_eq!(state.password_open, None);
    }

    /// The probe writes NOTHING
    #[test]
    fn the_read_changes_nothing_on_the_host() {
        let root = sandbox("read-only");
        with_keys(&root, Some(FAKE_KEY));
        sshd_saying(&root, Some("passwordauthentication yes\\n"));
        stub(&root, "systemctl", "echo 'the read reloaded sshd' >&2; exit 1");
        probe(&root);
        assert!(!drop_in_path(&root).exists(), "the read wrote the drop-in");
        assert!(
            std::fs::read_dir(root.join("etc/ssh/sshd_config.d")).unwrap().flatten().next().is_none(),
            "the read left something in the include directory"
        );
    }

    // ── The way back ────────────────────────────────────────────────────────

    #[test]
    fn removing_the_drop_in_opens_the_host_again() {
        let root = sandbox("open");
        std::fs::write(drop_in_path(&root), super::drop_in()).expect("a drop-in");
        sshd_saying(&root, Some("passwordauthentication yes\\n"));
        stub(&root, "systemctl", "exit 0");
        assert_eq!(open(&root), "opened");
        assert!(!drop_in_path(&root).exists());
    }

    #[test]
    fn a_host_this_product_never_closed_is_left_exactly_as_it_is() {
        let root = sandbox("already-open");
        std::fs::write(root.join("etc/ssh/sshd_config.d/50-cloud-init.conf"), "PasswordAuthentication no\n")
            .expect("somebody else's file");
        sshd_saying(&root, Some("passwordauthentication no\\n"));
        stub(&root, "systemctl", "echo 'reloaded for nothing' >&2; exit 1");
        assert_eq!(open(&root), "already-open");
        assert!(root.join("etc/ssh/sshd_config.d/50-cloud-init.conf").exists(),
                "a file this product did not write was removed");
    }

    #[test]
    fn a_configuration_that_is_broken_without_our_file_puts_it_back() {
        let root = sandbox("open-rejected");
        std::fs::write(drop_in_path(&root), super::drop_in()).expect("a drop-in");
        stub(&root, "sshd", "case \"$1\" in\n  -t) exit 1 ;;\nesac");
        stub(&root, "systemctl", "echo 'reloaded a rejected configuration' >&2; exit 0");
        assert_eq!(open(&root), "open-invalid-config");
        assert_eq!(std::fs::read_to_string(drop_in_path(&root)).unwrap(), super::drop_in());
    }

    #[test]
    fn a_host_closed_by_something_else_is_not_reported_open() {
        let root = sandbox("open-not-effective");
        std::fs::write(drop_in_path(&root), super::drop_in()).expect("a drop-in");
        sshd_saying(&root, Some("passwordauthentication no\\n"));
        stub(&root, "systemctl", "exit 0");
        assert_eq!(open(&root), "opened-not-effective");
        assert!(!drop_in_path(&root).exists());
    }

    #[test]
    fn a_daemon_that_will_not_reload_is_not_called_open() {
        let root = sandbox("open-no-reload");
        std::fs::write(drop_in_path(&root), super::drop_in()).expect("a drop-in");
        sshd_saying(&root, Some("passwordauthentication yes\\n"));
        stub(&root, "systemctl", "exit 1");
        assert_eq!(open(&root), "opened-not-reloaded");
    }

    #[test]
    fn the_backup_is_invisible_to_sshd_and_does_not_survive_a_success() {
        let root = sandbox("open-clean");
        std::fs::write(drop_in_path(&root), super::drop_in()).expect("a drop-in");
        sshd_saying(&root, Some("passwordauthentication yes\\n"));
        stub(&root, "systemctl", "exit 0");
        assert_eq!(open(&root), "opened");
        let left: Vec<String> = std::fs::read_dir(root.join("etc/ssh/sshd_config.d"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(left.is_empty(), "left behind: {left:?}");
        assert!(!format!("{}{}", super::DROP_IN_PATH, super::STAGED_SUFFIX).ends_with(".conf"));
    }

    // ── The parsing and the guards around the scripts ───────────────────────

    #[test]
    fn an_unreadable_probe_line_is_not_an_answer() {
        for text in ["", "open=maybe", "garbage", "open= key= dropin= sshd="] {
            let state = super::parse_state(text);
            assert_eq!(state.password_open, None, "{text:?}");
            assert!(!state.app_key_present, "{text:?}");
            assert!(!state.sshd_present, "{text:?}");
        }
    }

    #[test]
    fn anything_that_could_break_out_of_the_shell_literal_is_refused() {
        assert!(super::shell_safe("owner"));
        assert!(super::shell_safe(FAKE_KEY));
        assert!(!super::shell_safe("own'er"));
        assert!(!super::shell_safe("owner\nrm -rf /"));
        assert!(!super::shell_safe("owner\rrm -rf /"));
    }

    /// The read's answer file is not the write's
    #[test]
    fn the_read_and_the_write_do_not_share_an_answer_file() {
        assert_ne!(super::probe_verdict_path(), super::verdict_path());
        assert!(super::probe_verdict_path().starts_with(&super::verdict_path()));
    }

    #[test]
    fn every_verdict_the_button_can_produce_says_something() {
        for word in [
            "closed", "closed-not-reloaded", "closed-unverified", "not-written", "not-effective",
            "already-closed", "no-key", "invalid-config", "no-sshd", "opened", "already-open",
            "opened-not-reloaded", "opened-not-effective", "open-invalid-config",
        ] {
            let verdict = super::Verdict::parse(word).unwrap_or_else(|| panic!("{word} parses"));
            let sentence = super::verdict_sentence(&verdict, "owner");
            assert!(!sentence.trim().is_empty(), "{word}");
        }
    }
}

/// The per-account half: the file's shape and the guard, fired.
#[cfg(test)]
mod accounts {
    use super::*;
    use std::path::{Path, PathBuf};

    const FAKE_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake gryonixnexus-app";

    #[test]
    fn everyone_is_the_install_file_byte_for_byte() {
        assert_eq!(drop_in_for(&KeyOnly::Everyone), drop_in());
        assert_eq!(drop_in_for(&KeyOnly::Accounts(Vec::new())), drop_in());
    }

    #[test]
    fn the_named_drop_in_closes_its_match() {
        let text = drop_in_for(&KeyOnly::Accounts(vec!["alice".into(), "bob".into()]));
        assert!(text.contains("Match User alice,bob"), "{text}");
        assert!(text.trim_end().ends_with("Match all"), "the Match block is left open: {text}");
        let body = text.split("Match User").nth(1).expect("a block");
        assert!(body.contains("PasswordAuthentication no"), "{text}");
        assert!(body.contains("KbdInteractiveAuthentication no"), "{text}");
    }

    #[test]
    fn the_probe_is_read_one_account_per_line() {
        let users = parse_users(
            "user=root open=yes keys=no appkey=no\n\
             user=alice open=no keys=yes appkey=yes\n\
             user=bob open=unknown keys=yes appkey=no\n",
        );
        assert_eq!(users.len(), 3);
        assert_eq!(users[0].name, "root");
        assert_eq!(users[0].password_open, Some(true));
        assert!(!users[0].has_keys);
        assert_eq!(users[1].password_open, Some(false));
        assert!(users[1].app_key_present);
        assert_eq!(users[2].password_open, None);
    }

    fn sandbox(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sshd-users-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).expect("a sandbox");
        dir
    }

    fn stub(root: &Path, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = root.join("bin").join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("a stub");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("a stub");
    }

    /// Two accounts, and only the ones named here carry keys.
    fn host(root: &Path, with_keys: &[&str]) {
        let mut arms = String::new();
        for name in ["alice", "bob"] {
            let home = root.join("home").join(name);
            std::fs::create_dir_all(home.join(".ssh")).expect("a home");
            if with_keys.contains(&name) {
                std::fs::write(home.join(".ssh/authorized_keys"), format!("{FAKE_KEY}\n"))
                    .expect("keys");
            }
            arms.push_str(&format!(
                "  {name}) printf '{name}:x:1000:1000::{}:/bin/bash\\n' ;;\n",
                home.display()
            ));
        }
        stub(root, "getent", &format!("case \"$2\" in\n{arms}esac"));
        stub(root, "sshd", "case \"$1\" in\n  -t) exit 0 ;;\n  -T) printf 'passwordauthentication no\\nkbdinteractiveauthentication no\\n' ;;\nesac");
        stub(root, "systemctl", "exit 0");
    }

    fn run(root: &Path, names: &[&str]) -> (String, PathBuf) {
        let drop_in = root.join("etc/ssh/sshd_config.d/10-gryonixnexus-no-password.conf");
        let verdict_path = root.join("verdict");
        let owned: Vec<String> = names.iter().map(|name| name.to_string()).collect();
        let text = super::named_script(&owned, "alice", FAKE_KEY)
            .replace("/etc/ssh/sshd_config.d", &root.join("etc/ssh/sshd_config.d").display().to_string())
            .replace(super::VERDICT_PATH, &verdict_path.display().to_string());
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&text)
            .env("PATH", format!("{}:/usr/bin:/bin", root.join("bin").display()))
            .output()
            .expect("sh runs");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        (
            std::fs::read_to_string(&verdict_path).unwrap_or_default().trim().to_string(),
            drop_in,
        )
    }

    #[test]
    fn the_named_accounts_end_up_closed() {
        let root = sandbox("closed");
        host(&root, &["alice", "bob"]);
        let (verdict, drop_in) = run(&root, &["alice", "bob"]);
        assert_eq!(verdict, "closed");
        let text = std::fs::read_to_string(&drop_in).expect("the drop-in");
        assert!(text.contains("Match User alice,bob"), "{text}");
        assert!(text.trim_end().ends_with("Match all"), "{text}");
    }

    #[test]
    fn an_account_without_a_key_is_refused() {
        let root = sandbox("no-key");
        host(&root, &["alice"]);
        let (verdict, drop_in) = run(&root, &["alice", "bob"]);
        assert_eq!(verdict, "no-key");
        assert!(!drop_in.exists(), "a file was written for an account with no key");
    }

    #[test]
    fn a_rejected_configuration_keeps_the_previous_file() {
        let root = sandbox("rejected");
        host(&root, &["alice", "bob"]);
        assert_eq!(run(&root, &["alice"]).0, "closed");
        stub(&root, "sshd", "case \"$1\" in\n  -t) exit 1 ;;\nesac");
        let (verdict, drop_in) = run(&root, &["alice", "bob"]);
        assert_eq!(verdict, "invalid-config");
        let text = std::fs::read_to_string(&drop_in).expect("the previous file is back");
        assert!(text.contains("Match User alice\n"), "the older file was lost: {text}");
    }
}

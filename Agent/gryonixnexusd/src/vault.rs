//! The passwords of this deployment's own services, encrypted at rest by the agent

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

/// 24 bytes, the XChaCha nonce width.
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

pub struct VaultCipher {
    cipher: XChaCha20Poly1305,
}

impl VaultCipher {
    /// Reads the key at `path`, creating it on first use
    pub fn open(path: &Path) -> Result<Self> {
        match File::open(path) {
            Ok(mut file) => {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)
                    .with_context(|| format!("reading vault key {}", path.display()))?;
                if bytes.is_empty() {
                    // An empty key never sealed anything: an interrupted create.
                    std::fs::remove_file(path)
                        .with_context(|| format!("removing empty vault key {}", path.display()))?;
                    return Self::create(path);
                }
                if bytes.len() != KEY_LEN {
                    return Err(anyhow!(
                        "vault key {} is {} bytes, expected {KEY_LEN} — refusing to replace it, \
                         because a new key would orphan every stored password",
                        path.display(),
                        bytes.len()
                    ));
                }
                Self::from_bytes(&bytes)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Self::create(path),
            Err(err) => Err(err).with_context(|| format!("opening vault key {}", path.display())),
        }
    }

    fn create(path: &Path) -> Result<Self> {
        let bytes = random_bytes(KEY_LEN)?;
        let staged = path.with_extension(format!("tmp-{}", std::process::id()));
        let _ = std::fs::remove_file(&staged);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staged)
            .with_context(|| format!("creating vault key {}", staged.display()))?;
        let written = file.write_all(&bytes).and_then(|_| file.sync_all());
        drop(file);
        let linked = written.and_then(|_| std::fs::hard_link(&staged, path));
        let _ = std::fs::remove_file(&staged);
        linked.with_context(|| format!("creating vault key {}", path.display()))?;
        Self::from_bytes(&bytes)
    }

    #[cfg(test)]
    pub fn ephemeral() -> Result<Self> {
        Self::from_bytes(&random_bytes(KEY_LEN)?)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key = Key::from_slice(bytes);
        Ok(Self {
            cipher: XChaCha20Poly1305::new(key),
        })
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let nonce_bytes = random_bytes(NONCE_LEN)?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| anyhow!("sealing a vault entry failed"))?;
        Ok((ciphertext, nonce_bytes))
    }

    pub fn unseal(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != NONCE_LEN {
            return Err(anyhow!("vault nonce is {} bytes, expected {NONCE_LEN}", nonce.len()));
        }
        let nonce = XNonce::from_slice(nonce);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("a vault entry did not decrypt — wrong key, or the row was altered"))
    }
}

fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    File::open("/dev/urandom")
        .context("opening /dev/urandom")?
        .read_exact(&mut buf)
        .context("reading /dev/urandom")?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_sealed_entry_comes_back_as_itself() {
        let cipher = VaultCipher::ephemeral().unwrap();
        let (sealed, nonce) = cipher.seal(b"hunter2").unwrap();
        assert_eq!(cipher.unseal(&sealed, &nonce).unwrap(), b"hunter2");
    }

    #[test]
    fn the_stored_bytes_do_not_contain_the_password() {
        let cipher = VaultCipher::ephemeral().unwrap();
        let (sealed, _nonce) = cipher.seal(b"correct-horse-battery-staple").unwrap();
        assert!(!contains(&sealed, b"correct-horse"), "the ciphertext carries the plaintext");
    }

    #[test]
    fn two_seals_of_the_same_text_differ() {
        let cipher = VaultCipher::ephemeral().unwrap();
        let (a, _) = cipher.seal(b"same").unwrap();
        let (b, _) = cipher.seal(b"same").unwrap();
        assert_ne!(a, b, "the nonce is not being varied per write");
    }

    #[test]
    fn a_tampered_row_fails_instead_of_decrypting() {
        let cipher = VaultCipher::ephemeral().unwrap();
        let (mut sealed, nonce) = cipher.seal(b"hunter2").unwrap();
        sealed[0] ^= 0xff;
        assert!(cipher.unseal(&sealed, &nonce).is_err());
    }

    #[test]
    fn another_key_cannot_read_it() {
        let mine = VaultCipher::ephemeral().unwrap();
        let theirs = VaultCipher::ephemeral().unwrap();
        let (sealed, nonce) = mine.seal(b"hunter2").unwrap();
        assert!(theirs.unseal(&sealed, &nonce).is_err());
    }

    #[test]
    fn the_key_file_is_created_0600_and_reused() {
        let dir = std::env::temp_dir().join(format!("gryonix-vault-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.key");
        let _ = std::fs::remove_file(&path);

        let first = VaultCipher::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the vault key is readable by somebody else");

        let (sealed, nonce) = first.seal(b"hunter2").unwrap();
        let second = VaultCipher::open(&path).unwrap();
        assert_eq!(second.unseal(&sealed, &nonce).unwrap(), b"hunter2");

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_key_file_of_the_wrong_length_is_refused_rather_than_replaced() {
        let dir = std::env::temp_dir().join(format!("gryonix-vault-short-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.key");
        std::fs::write(&path, b"too short").unwrap();
        let err = match VaultCipher::open(&path) {
            Ok(_) => panic!("a short key file was accepted"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("refusing to replace"), "got: {err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"too short");
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_empty_key_file_from_an_interrupted_create_is_replaced() {
        let dir = std::env::temp_dir().join(format!("gryonix-vault-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.key");
        std::fs::write(&path, b"").unwrap();

        let cipher = VaultCipher::open(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap().len(), KEY_LEN);
        let (sealed, nonce) = cipher.seal(b"x").unwrap();
        assert_eq!(VaultCipher::open(&path).unwrap().unseal(&sealed, &nonce).unwrap(), b"x");
        let leftovers = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(leftovers, 1, "the staged key was left behind");
        std::fs::remove_dir_all(&dir).ok();
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}

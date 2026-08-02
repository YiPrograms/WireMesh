use std::{path::Path, sync::Arc};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand::RngCore;
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;
use zeroize::Zeroizing;

const ENVELOPE_VERSION: u8 = 1;
const NONCE_LENGTH: usize = 24;

#[derive(Clone)]
pub struct SecretBox {
    key: Arc<Zeroizing<[u8; 32]>>,
}

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("master key must be exactly 32 raw bytes or base64-encoded 32 bytes")]
    InvalidMasterKey,
    #[error("secret envelope is malformed or has an unsupported version")]
    InvalidEnvelope,
    #[error("secret envelope authentication failed")]
    Authentication,
    #[error("secret value could not be encoded: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("read master key: {0}")]
    Read(#[from] std::io::Error),
}

impl SecretBox {
    pub async fn from_file(path: &Path) -> Result<Self, SecretError> {
        let bytes = tokio::fs::read(path).await?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SecretError> {
        let decoded = if bytes.len() == 32 {
            bytes.to_vec()
        } else {
            let trimmed = trim_ascii(bytes);
            STANDARD
                .decode(trimmed)
                .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
                .map_err(|_| SecretError::InvalidMasterKey)?
        };
        let key: [u8; 32] = decoded
            .try_into()
            .map_err(|_| SecretError::InvalidMasterKey)?;
        Ok(Self {
            key: Arc::new(Zeroizing::new(key)),
        })
    }

    pub fn encrypt<T: Serialize>(&self, context: &str, value: &T) -> Result<Vec<u8>, SecretError> {
        let plaintext = Zeroizing::new(serde_json::to_vec(value)?);
        let mut nonce = [0_u8; NONCE_LENGTH];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref().as_slice())
            .map_err(|_| SecretError::InvalidMasterKey)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| SecretError::Authentication)?;
        let mut envelope = Vec::with_capacity(1 + NONCE_LENGTH + ciphertext.len());
        envelope.push(ENVELOPE_VERSION);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    pub fn decrypt<T: DeserializeOwned>(
        &self,
        context: &str,
        envelope: &[u8],
    ) -> Result<T, SecretError> {
        if envelope.first().copied() != Some(ENVELOPE_VERSION)
            || envelope.len() <= 1 + NONCE_LENGTH
        {
            return Err(SecretError::InvalidEnvelope);
        }
        let nonce = &envelope[1..1 + NONCE_LENGTH];
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref().as_slice())
            .map_err(|_| SecretError::InvalidMasterKey)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: &envelope[1 + NONCE_LENGTH..],
                        aad: context.as_bytes(),
                    },
                )
                .map_err(|_| SecretError::Authentication)?,
        );
        Ok(serde_json::from_slice(&plaintext)?)
    }
}

pub fn generate_master_key() -> String {
    let mut key = Zeroizing::new([0_u8; 32]);
    rand::rngs::OsRng.fill_bytes(key.as_mut());
    STANDARD.encode(key.as_slice())
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Credential {
        password: String,
    }

    #[test]
    fn envelope_uses_context_as_authenticated_data() {
        let vault = SecretBox::from_bytes(&[9_u8; 32]).unwrap();
        let value = Credential {
            password: "secret".into(),
        };
        let envelope = vault.encrypt("provider:a", &value).unwrap();
        assert_eq!(
            vault
                .decrypt::<Credential>("provider:a", &envelope)
                .unwrap(),
            value
        );
        assert!(vault.decrypt::<Credential>("provider:b", &envelope).is_err());
    }
}

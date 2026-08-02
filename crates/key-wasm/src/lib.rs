use base64::{Engine, engine::general_purpose::STANDARD};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[wasm_bindgen]
pub struct WireGuardKeyPair {
    private_key: Zeroizing<String>,
    public_key: String,
}

#[wasm_bindgen]
impl WireGuardKeyPair {
    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> String {
        self.private_key.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> String {
        self.public_key.clone()
    }
}

#[wasm_bindgen]
pub fn generate_keypair() -> WireGuardKeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    WireGuardKeyPair {
        private_key: Zeroizing::new(STANDARD.encode(secret.to_bytes())),
        public_key: STANDARD.encode(public.as_bytes()),
    }
}

#[wasm_bindgen]
pub fn derive_public_key(private_key: &str) -> Result<String, JsError> {
    let decoded = Zeroizing::new(
        STANDARD
            .decode(private_key.trim())
            .map_err(|_| JsError::new("private key is not valid base64"))?,
    );
    let bytes: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| JsError::new("private key must contain 32 bytes"))?;
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    Ok(STANDARD.encode(public.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_pair_round_trips() {
        let pair = generate_keypair();
        assert_eq!(
            derive_public_key(&pair.private_key()).unwrap(),
            pair.public_key()
        );
    }
}

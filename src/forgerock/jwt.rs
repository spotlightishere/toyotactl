use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

use super::ForgeRockError;

/// We need the `sub` value from our token as a GUID within the API.
#[derive(Deserialize)]
struct TokenData {
    pub sub: String,
    pub exp: u64,
}

/// An extraordinarily, hilariously basic JWT parser.
pub fn get_sub(token: &str) -> Result<String, ForgeRockError> {
    // There's three components to a JWT: its header, its payload, and signature.
    // These are separated by `.`s, and are all JSON encoded.
    //
    // First, let's separate these parts from our string.
    let components: Vec<&str> = token.split('.').collect();
    if components.len() != 3 {
        return Err(ForgeRockError::InvalidToken);
    }

    // We don't care too much about validating the JWT here,
    // as the API itself will do all of that for us.
    // If the user provides us a fake JWT, that's not for us to handle.
    //
    // As such, we'll ignore the header and signature, and only parse the payload.
    let encoded_payload = components[1];

    // Components of JWTs are base64-encoded JSON strings, using the URL-safe, non-padded character set.
    //
    // These all produce errors we don't particularly care about handling in specific,
    // so let's just blankly map them away. It looks rather disgusting, but it works...
    let decoded_payload = URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .expect("should be able to decode JWT payload");
    let payload_json =
        str::from_utf8(&decoded_payload).expect("should be able to decode JWT payload");
    let payload_contents: TokenData =
        serde_json::from_str(payload_json).expect("should be able to parse JWT payload");

    // The only validation we'll do: let's evaluate our expiry.
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expiry = payload_contents.exp;
    if current_timestamp >= expiry {
        return Err(ForgeRockError::ExpiredToken);
    };

    // We're done! All we need is the sub (used as a GUID within the API).
    Ok(payload_contents.sub)
}

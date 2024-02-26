mod forgerock;
use crate::forgerock::AuthCredentials;

#[tokio::main]
async fn main() {
    // TODO(spotlightishere): Move credentials to the keychain or similar
    let credentials = AuthCredentials {
        username: "".to_string(),
        password: "".to_string(),
    };
    forgerock::authenticate(credentials)
        .await
        .expect("should be able to authenticate");
}

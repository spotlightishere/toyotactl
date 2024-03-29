mod forgerock;
use crate::forgerock::AuthCredentials;

#[tokio::main]
async fn main() {
    // TODO(spotlightishere): Move credentials to the keychain or similar
    let credentials = AuthCredentials {
        username: "".to_string(),
        password: "".to_string(),
    };
    let token_id = forgerock::authenticate(credentials)
        .await
        .expect("should be able to authenticate");
    println!("got a token: {}", token_id);

    let (access_token, refresh_token) = forgerock::obtain_access_token(token_id)
        .await
        .expect("should be able to authorize");
}

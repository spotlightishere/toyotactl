use super::authorize::perform_authorize_request;
use super::http_client::{HttpError, OAUTH_CLIENT_ID, OAUTH_REDIRECT_URI};

/// The endpoint leveraged for obtaining an access token.
const ACCESS_TOKEN_ENDPOINT: &str =
    "https://login.toyotadriverslogin.com/oauth2/realms/root/realms/tmna-native/access_token";

/// Attempt to obtain an access token via OAuth2.
/// We authenticate via the `token_id` obtained within the authentication flow.
pub async fn obtain_access_token(token_id: String) -> Result<(String, String), HttpError> {
    // Obtain an authorization code from the given token ID.
    let authorize_code = perform_authorize_request(token_id).await?;
    let result = reqwest::Client::new()
        .post(ACCESS_TOKEN_ENDPOINT)
        .query(&[
            ("client_id", OAUTH_CLIENT_ID),
            ("redirect_uri", OAUTH_REDIRECT_URI),
            ("grant_type", "authorization_code"),
            ("code_verifier", "plain"),
            ("code", &authorize_code),
        ])
        .send()
        .await
        .map_err(HttpError::Reqwest)?;

    let lol = result.text().await.unwrap();
    println!("{:?}", lol);

    Ok(("lol".to_string(), "lol".to_string()))
}

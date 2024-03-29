use super::{storage::CredentialStorage, ForgeRockError, OAUTH_CLIENT_ID, OAUTH_REDIRECT_URI};

/// The endpoint leveraged for obtaining an access token.
const ACCESS_TOKEN_ENDPOINT: &str =
    "https://login.toyotadriverslogin.com/oauth2/realms/root/realms/tmna-native/access_token";

/// Attempt to obtain an access token via OAuth2.
/// We authenticate via the `token_id` obtained within the authentication flow.
pub async fn obtain_access_token(
    authorize_code: String,
) -> Result<CredentialStorage, ForgeRockError> {
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
        .map_err(ForgeRockError::Reqwest)?;

    // We'll reuse CredentialStorage from the primary `forgerock` module
    // because it also has `access_token` and `refresh_token` fields,
    // which is all we need to care about from this response.
    if !result.status().is_success() {
        // TODO(spotlightishere): Handle this better!
        println!("Hmm... something has gone awry: {:?}", result.text().await);
        panic!("Hell has frozen over");
    }

    let response_text = result.text().await.map_err(ForgeRockError::Reqwest)?;
    println!("access token body: {}", response_text);

    match serde_json::from_str(response_text.as_str()) {
        Ok(body) => Ok(body),
        Err(error) => Err(ForgeRockError::Parse(error)),
    }
}

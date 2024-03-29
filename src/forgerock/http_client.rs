use reqwest::Client;
use serde::Serialize;

use crate::forgerock::authenticate::AuthenticateFormat;

/// Possible HTTP error types.
#[derive(Debug)]
pub enum HttpError {
    Reqwest(reqwest::Error),
    Parse(serde_json::Error),
    Response,
    OAuth2,
}

/// The shared redirect URI across all OAuth2 requests.
pub const OAUTH_REDIRECT_URI: &str = "com.toyota.oneapp:/oauth2Callback";

/// Simialrly, the shared client ID across all OAuth2 requests.
pub const OAUTH_CLIENT_ID: &str = "oneappsdkclient";

/// The path to the authenticate endpoint using ForgeRock AM.
const AUTHENTICATE_ENDPOINT: &str =
    "https://login.toyotadriverslogin.com/json/realms/root/realms/tmna-native/authenticate";

/// Creates and executes the actual authentication request with the given client.
pub async fn authenticate_request<T: Serialize>(json: T) -> Result<AuthenticateFormat, HttpError> {
    // We'll need to serialize our text to begin with.
    let posted_contents =
        serde_json::to_string(&json).expect("should have valid JSON to POST with");
    println!("About to post: {}", posted_contents);

    // There are several necessary components to our authenticate request:
    let result = Client::new()
        .post(AUTHENTICATE_ENDPOINT)
        // We must specify we're POSTing JSON, and an acceptable API version.
        .header("Content-Type", "application/json")
        .header("Accept-API-Version", "resource=2.1, protocol=1.0")
        // ForgeRock documents that you must specify an auth index "type".
        // We use the "service" type with "OneAppSignIn" so that we can log in.
        // (For registeration, there is also "OneAppSignUp".)
        .query(&[
            ("authIndexType", "service"),
            ("authIndexValue", "OneAppSignIn"),
        ])
        .body(posted_contents)
        .send()
        .await
        .map_err(HttpError::Reqwest)?;

    // Let's ensure that we made this request successfully.
    // We (naively) assume that any request resulting in an error
    // will have a non-200 response code.
    if !result.status().is_success() {
        // TODO(spotlightishere): Handle this better!
        println!("Hmm... something has gone awry: {:?}", result.text().await);
        panic!("Hell has frozen over");
    }

    // Finally, we can serialize to our expected format.
    let response_text = result.text().await.map_err(HttpError::Reqwest)?;
    println!("body: {}", response_text);

    match serde_json::from_str(response_text.as_str()) {
        Ok(body) => Ok(body),
        Err(error) => Err(HttpError::Parse(error)),
    }
}

use super::http_client::{HttpError, OAUTH_CLIENT_ID, OAUTH_REDIRECT_URI};
use reqwest::{header, StatusCode};
use std::collections::HashMap;
use url::Url;

/// The path to authorization endpoint via ForgeRock AM.
/// ("Authorize" should be read in the context of OAuth2, and not the previous custom authentication flow.)
const AUTHORIZATION_ENDPOINT: &str =
    "https://login.toyotadriverslogin.com/oauth2/realms/root/realms/tmna-native/authorize";

/// Performs OAuth2 authorization, obtaining a code we can exchange for an access token.
pub async fn perform_authorize_request(token_id: String) -> Result<String, HttpError> {
    let result = reqwest::Client::new()
        .get(AUTHORIZATION_ENDPOINT)
        // We only have to deviate once here: we must set our obtained token as a cookie.
        .header(header::COOKIE, format!("iPlanetDirectoryPro={token_id}"))
        // Standard OAuth2 query parameters.
        .query(&[
            ("client_id", OAUTH_CLIENT_ID),
            ("scope", "openid profile write"),
            ("response_type", "code"),
            ("redirect_uri", OAUTH_REDIRECT_URI),
            ("code_challenge", "plain"),
            ("code_challenge_method", "plain"),
        ])
        .send()
        .await
        .map_err(HttpError::Reqwest)?;

    // We should be given 302 Found, and redirected to the OAuth2 URL.
    if result.status() != StatusCode::FOUND {
        panic!("Invalid authorization request response!");
    }
    let Some(location_header) = result.headers().get(header::LOCATION) else {
        panic!("Unable to find redirection location in authorization request response!");
    };

    // We should now be able to parse this location.
    let location_str = location_header
        .to_str()
        .expect("should be able to obtain location header string");
    let location = Url::parse(location_str).expect("should be able to parse location header URL");

    // Our OAuth2 authorization code should be present within the "code" query parameter.
    let query_parameters: HashMap<String, String> = location.query_pairs().into_owned().collect();
    match query_parameters.get("code") {
        Some(oauth2_code) => Ok(oauth2_code.to_string()),
        None => Err(HttpError::OAuth2),
    }
}

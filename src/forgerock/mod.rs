mod authenticate;
mod authorize;
mod oauth_client;
mod storage;

/// Possible error types while working with ForgeRock.
#[derive(Debug)]
pub enum ForgeRockError {
    AuthError,
    Reqwest(reqwest::Error),
    Parse(serde_json::Error),
    OAuth2,
    ApiClientError(crate::api::ApiError),
}

/// The shared redirect URI across all OAuth2 requests.
pub const OAUTH_REDIRECT_URI: &str = "com.toyota.oneapp:/oauth2Callback";

/// Simialrly, the shared client ID across all OAuth2 requests.
pub const OAUTH_CLIENT_ID: &str = "oneappsdkclient";

pub use storage::login;

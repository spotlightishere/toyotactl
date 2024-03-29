use super::authenticate::{self, AuthCredentials};
use crate::{
    api::ApiClient,
    forgerock::{authorize, oauth_client},
};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::{io, io::Write};

/// Possible error types while working with ForgeRock.
#[derive(Debug)]
pub enum ForgeRockError {
    AuthError,
    Reqwest(reqwest::Error),
    Parse(serde_json::Error),
    Response,
    OAuth2,
    CredentialStorage(keyring::Error),
    ApiClientError(crate::api::ApiError),
}

/// The shared redirect URI across all OAuth2 requests.
pub const OAUTH_REDIRECT_URI: &str = "com.toyota.oneapp:/oauth2Callback";

/// Simialrly, the shared client ID across all OAuth2 requests.
pub const OAUTH_CLIENT_ID: &str = "oneappsdkclient";

/// The format of our JSON within our credential storage.
///
/// While we would ideally have one credential per token type,
/// it proved to be a pain to ensure both would exist.
#[derive(Deserialize, Serialize)]
pub struct CredentialStorage {
    pub access_token: String,
    pub refresh_token: String,
}

impl CredentialStorage {
    pub fn from_string(contents: String) -> Self {
        serde_json::from_str(contents.as_str()).expect("should be able to parse credential JSON")
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(&self).expect("should be able to serialize credential JSON")
    }
}

/// Retrieves a valid access token from the user's storage.
/// If not possible, the user will be requested to reauthenticate.
pub async fn login() -> Result<ApiClient, ForgeRockError> {
    let credentials_entry = Entry::new("toyotactl", "OAuth2 Credentials")
        .expect("should be able to retrieve OAuth2 credentials");

    // Do we have existing access tokens/refresh tokens in the user's keyring?
    let credential_storage = credentials_entry.get_password();
    let Ok(credential_contents) = credential_storage else {
        // We have no password stored.
        // Let's request for the user to enter, and update our storage.
        let storage = request_username_password().await?;
        credentials_entry
            .set_password(&storage.to_string())
            .expect("should be able to update stored OAuth2 credentials");

        // TODO(spotlightishere): Find a nicer arrangement to handle errors when creating the client
        return ApiClient::new(storage.access_token).map_err(ForgeRockError::ApiClientError);
    };

    // We do have tokens. Parse.
    let storage = CredentialStorage::from_string(credential_contents);

    // TODO(spotlightishere): Handle actually using refresh tokens
    ApiClient::new(storage.access_token).map_err(ForgeRockError::ApiClientError)
}

pub fn interactive_prompt(prompt_type: &str) -> String {
    let mut response = String::new();
    print!("Please enter {prompt_type} for your Toyota account: ");
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut response)
        .expect("should be able to read response");

    // Remove newline
    response.truncate(response.len() - 1);
    response
}

/// Interactively request the user for their username and password.
pub async fn request_username_password() -> Result<CredentialStorage, ForgeRockError> {
    let credentials = AuthCredentials {
        username: interactive_prompt("your username"),
        password: interactive_prompt("your password"),
    };

    let token_id = authenticate::authenticate(credentials)
        .await
        .expect("should be able to authenticate");
    println!("got a token: {}", token_id);

    // Obtain an authorization code from the given token ID.
    let authorize_code = authorize::perform_authorize_request(token_id)
        .await
        .expect("should be able to authorize");
    println!("got a code: {}", authorize_code);

    let credentials = oauth_client::obtain_access_token(authorize_code)
        .await
        .expect("should be able to obtain access token");

    Ok(credentials)
}

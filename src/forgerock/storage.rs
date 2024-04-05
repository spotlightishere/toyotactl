use super::authenticate::{self, AuthCredentials};
use super::ForgeRockError;
use crate::{
    api::ApiClient,
    forgerock::{authorize, jwt, oauth_client},
};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::{io, io::Write};

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
    pub fn from_json(contents: String) -> Self {
        serde_json::from_str(contents.as_str()).expect("should be able to parse credential JSON")
    }

    pub fn to_json(&self) -> String {
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
        //
        // TODO(spotlightishere): Find a nicer arrangement to handle errors when creating the client
        return request_username_password(credentials_entry).await;
    };

    // We do have tokens! Parse.
    let storage = CredentialStorage::from_json(credential_contents);

    // Let's ensure our access token has not yet expired.
    // While validating, we'll also obtain the necessary `sub` value - used as a GUID within the API.
    //
    // If we were successful, we have a JWT `sub` to use for our API client.
    // If we were given an expired token, we'll refresh it momentarily.
    // However, if we were given any other error, we need to stop here.
    match jwt::get_sub(&storage.access_token) {
        Ok(jwt_sub) => return Ok(ApiClient::new(storage.access_token, jwt_sub)),
        Err(ForgeRockError::ExpiredToken) => {}
        Err(err) => return Err(err),
    };

    // TODO(spotlightishere): This is a mess. Can we make it cleaner?
    // We'll reuse the same as above, but with our refresh token.
    //
    // If we were successful, we can continue and refresh.
    // If we were given an expired token, the user needs to re-authenticate.
    // However, if we were given any other error, we need to stop here.
    match jwt::get_sub(&storage.refresh_token) {
        Ok(_) => {}
        Err(ForgeRockError::ExpiredToken) => {
            return request_username_password(credentials_entry).await
        }
        Err(err) => return Err(err),
    };

    // Refresh!
    let refreshed_tokens = oauth_client::refresh_tokens(storage.refresh_token).await?;
    credentials_entry
        .set_password(&refreshed_tokens.to_json())
        .expect("should be able to update stored OAuth2 credentials");

    // Similar to username/password authentication below, we should be able to
    // obtain a JWT sub as this token was just issued via refresh.
    let jwt_sub = jwt::get_sub(&refreshed_tokens.access_token)?;

    Ok(ApiClient::new(refreshed_tokens.access_token, jwt_sub))
}

/// Quick and dirty function to read input from the user.
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
/// We store the given tokens after authentication, and create an ``ApiClient`` around them.
pub async fn request_username_password(
    credentials_entry: Entry,
) -> Result<ApiClient, ForgeRockError> {
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

    credentials_entry
        .set_password(&credentials.to_json())
        .expect("should be able to update stored OAuth2 credentials");

    // We should be able to obtain a JWT sub because this token was (theoretically) just issued.
    // TODO(spotlightishere): Find a nicer arrangement to handle errors when creating the client
    let jwt_sub = jwt::get_sub(&credentials.access_token)?;
    Ok(ApiClient::new(credentials.access_token, jwt_sub))
}

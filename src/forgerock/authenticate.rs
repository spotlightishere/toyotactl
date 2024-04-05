use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{io, io::Write};
use uuid::Uuid;

use super::ForgeRockError;

/// The high-level response format from authentication.
/// Please refer to the ``authenticate`` function for its format.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateFormat {
    /// A JWT token containing session information.
    /// Only present for as long as the authentication tango continues.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_id: Option<String>,
    /// Callbacks the client must perform in order to be authenticated.
    ///
    /// Similarly only present for as long as the authentication tango continues.
    /// We default it to be an empty Vec to avoid all sorts of ownership woes.
    /// TODO(spotlightishere): This is a mess :(
    #[serde(default = "Vec::new", skip_serializing_if = "Vec::is_empty")]
    pub callbacks: Vec<AuthenticationCallback>,

    /// A token usable to begin OAuth2 authorization.
    /// Only present once authentication is complete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
}

/// An individual callback the client is expected to perform and provide.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AuthenticationCallback {
    /// The `type` of callback this client must handle.
    #[serde(rename = "type")]
    pub callback_type: String,
    /// Server-side provided information over this callback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Vec<ValuePair>>,
    /// Information the client must provide when responding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<Vec<ValuePair>>,
    /// Hidden identifier that shows up with multiple callbacks.
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<u32>,
}

/// A simple key-value pair.
/// Observed values are an array of strings, and strings alone.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValuePair {
    pub name: String,
    pub value: serde_json::Value,
}

/// The user's username and password, in a struct out of ease.
pub struct AuthCredentials {
    pub username: String,
    pub password: String,
}

/// The path to the authenticate endpoint using ForgeRock AM.
const AUTHENTICATE_ENDPOINT: &str =
    "https://login.toyotadriverslogin.com/json/realms/root/realms/tmna-native/authenticate";

/// Creates and executes the actual authentication request with the given client.
pub async fn perform_authenticate_request<T: Serialize>(
    json: T,
) -> Result<AuthenticateFormat, ForgeRockError> {
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
        .map_err(ForgeRockError::Reqwest)?;

    // Let's ensure that we made this request successfully.
    // We (naively) assume that any request resulting in an error
    // will have a non-200 response code.
    if !result.status().is_success() {
        // TODO(spotlightishere): Handle this better!
        println!("Hmm... something has gone awry: {:?}", result.text().await);
        panic!("Hell has frozen over");
    }

    // Finally, we can serialize to our expected format.
    let response_text = result.text().await.map_err(ForgeRockError::Reqwest)?;
    println!("body: {}", response_text);

    match serde_json::from_str(response_text.as_str()) {
        Ok(body) => Ok(body),
        Err(error) => Err(ForgeRockError::Parse(error)),
    }
}

/// Begin the authentication tango.
///
/// ForgeRock's AM product has... a design, for certain.
/// There are multiple steps to the authentication route in which the client is
/// expected to incrementally add data to "callbacks" of various types.
///
/// For example, given an initial server response of:
/// ```json
/// {
///     "authId": "eyJ[..]",
///     "callbacks": [
///         {
///             "type": "NameCallback",
///             "output": [
///                 {
///                     "name": "prompt",
///                     "value": "ui_locales"
///                 }
///             ],
///             "input": [
///                 {
///                     "name": "IDToken1",
///                     "value": ""
///                 }
///             ]
///         }
///     ]
/// }
/// ```
///
/// The client would be expected to send back the *exact same* JSON object, but
/// with the first input's `value` set to their device locale (e.g. `en-US`).
/// There are several types of callback types, and we only handle a few.
pub async fn authenticate(credentials: AuthCredentials) -> Result<String, ForgeRockError> {
    // We must now loop through all possible callbacks until we get
    // a final token that we can handle, or until we receive an error.
    //
    // First, make a request with an empty body to obtain our initial callback.
    // We assume that this should always be our authentication format.
    let mut response = perform_authenticate_request("").await?;

    // Let's loop for no more than 15 times to allow repeating if
    // the user makes a mistake with their username, password, or OTP code.
    let mut callback_count = 0;
    while callback_count < 15 {
        // We'll immediately our response as we need to update its format within future requests.
        let mut working_body = response.clone();

        // If we're given a token, we have completed our authentication tango.
        if let Some(token_id) = response.token_id {
            return Ok(token_id);
        }

        // With no provided token, we should continue the authentication tango.
        // If we have no auth ID and no callbacks, then something else is awry.
        if working_body.auth_id.is_some() && working_body.callbacks.is_empty() {
            // TODO(spotlightishere) Convert to a proper error
            panic!("No authentication ID, or no callbacks!");
        };

        // We now must handle all callbacks.
        for callback in working_body.callbacks.iter_mut() {
            callback.process(&credentials);
        }

        // println!("{:?}", working_body);
        // We now make the request once more but with our adapted body.
        response = perform_authenticate_request(working_body).await?;
        callback_count += 1;
    }

    // If we've failed to obtain a token within 15 attempts, cease.
    Err(ForgeRockError::Auth)
}

impl AuthenticationCallback {
    /// Process and handle all necessary inputs/outputs for this callback.
    pub fn process(&mut self, credentials: &AuthCredentials) {
        let callback_type = self.callback_type.as_str();
        println!("Callback type: {}", self.callback_type);

        // Not every callback type has inputs.
        if callback_type == "TextOutputCallback" {
            return;
        }

        // Frustratingly, not every output has a corresponding input.
        // We'll iterate through pairs and handle as necessary.
        //
        // TODO(spotlightishere): Properly determine instead of forcibly unwrapping
        let mut output_iter = self.output.as_mut().unwrap().iter_mut();
        let mut input_iter = self.input.as_mut().unwrap().iter_mut();

        // TODO(spotlightishere): This design is a mess with all the different types :(
        // Can this design be refactored?
        match (callback_type, output_iter.next(), input_iter.next()) {
            ("NameCallback", Some(output), Some(input)) => {
                // The name callback can, frustratingly, be used in several ways.
                // We can verify based on the "prompt" within the first output.
                let prompt_name = &output.value;
                if prompt_name == "ui_locales" {
                    // We need to set the device's UI locale, e.g. en-US.
                    // We'll hardcode this for our own sake.
                    input.value = json!("en-US");
                } else if prompt_name == "User Name" {
                    // We'll use the user's specified name.
                    input.value = json!(credentials.username);
                } else {
                    unimplemented!("unknown name callback prompt name: {}", prompt_name)
                }
            }
            ("PasswordCallback", Some(output), Some(input)) => {
                // Password callbacks handle both passwords and OTP values.
                let prompt_name = &output.value;
                if prompt_name == "Password" {
                    input.value = json!(credentials.password);
                } else if prompt_name == "One Time Password" {
                    // TODO(spotlightishere): We probably shouldn't be just randomly requesting input here...
                    let mut otp_code = String::new();
                    print!("Please enter the OTP code you were just emailed/texted: ");
                    io::stdout().flush().unwrap();

                    io::stdin()
                        .read_line(&mut otp_code)
                        .expect("should be able to read OTP code");
                    // Remove newline
                    otp_code.truncate(otp_code.len() - 1);
                    input.value = json!(otp_code);
                } else {
                    unimplemented!("unknown password callback prompt name: {}", prompt_name)
                }
            }
            ("HiddenValueCallback", _, Some(input)) => {
                // TODO(spotlightishere) There's likely more than one possible value than `devicePrint`
                // with HiddenValueCallback, but this appears to be the only one handled by the SDK as of writing.
                let hardware_id = Uuid::new_v4();
                // The fingerprint must be a string containing JSON.
                let device_fingerprint = json!({
                    "appId": "com.toyota.oneapp",
                    "biometricEnabled": "false",
                    "deviceType": "Android",
                    // Oddly, this value is hardcoded to "real".
                    "emulator": "real",
                    "geolocation": null,
                    // A randomly generated UUID, not persisted.
                    "hardwareId": hardware_id,
                    "language": "en",
                    "model": "Pixel",
                    // The device's brand string, along with its build user.
                    "brand": "Google android-build",
                    "pushTokenId": null,
                    // The SDK/API version.
                    "systemOS": "34",
                    "timeZone": "America/New_York"
                })
                .to_string();

                input.value = json!(device_fingerprint);
            }
            ("ChoiceCallback", _, _) => {
                // Observed choices have been related to password resets,
                // resending verification codes, choosing social media auth, etc.
                //
                // TODO(spotlightishere): Change if necessary
            }
            ("ConfirmationCallback", _, _) => {
                // This callback type has verify/resend options.
                // The default is to verify, so we do nothing.
                //
                // TODO(spotlightishere): Change if necessary
            }
            (_, _, _) => {
                println!("{:?}", self);
                unimplemented!("unknown callback type: {}", callback_type);
            }
        }
    }
}

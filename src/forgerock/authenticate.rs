use crate::forgerock::constants;
use rand::distributions::{Alphanumeric, DistString};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// The high-level response format from authentication.
/// Please refer to the ``authenticate`` function for its format.
#[derive(Deserialize, Serialize, Debug, Clone)]
struct AuthenticateFormat {
    /// A JWT token containing session information.
    #[serde(rename = "authId")]
    pub auth_id: String,
    /// Callbacks the client must perform in order to be authenticated.
    pub callbacks: Vec<AuthenticationCallback>,
}

/// An individual callback the client is expected to perform and provide.
#[derive(Deserialize, Serialize, Debug, Clone)]
struct AuthenticationCallback {
    /// The `type` of callback this client must handle.
    #[serde(rename = "type")]
    pub callback_type: String,
    /// Server-side provided information over this callback.
    pub output: Vec<ValuePair>,
    /// Information the client must provide when responding.
    pub input: Vec<ValuePair>,
    /// Hidden identifier that shows up with multiple callbacks.
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<u32>,
}

/// A simple key-value pair.
/// Observed values are an array of strings, and strings alone.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct ValuePair {
    pub name: String,
    pub value: serde_json::Value,
}

/// The user's username and password, in a struct out of ease.
pub struct AuthCredentials {
    pub username: String,
    pub password: String,
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
pub async fn authenticate(credentials: AuthCredentials) -> Result<(), reqwest::Error> {
    // We must now loop through all possible callbacks until we get
    // a final token that we can handle, or until we receive an error.
    let client = reqwest::Client::new();

    // First, make a request with an empty body to obtain our initial callback.
    let mut response = authenticate_request(&client, "").await;
    // println!("{:?}", response);

    loop {
        // We'll immediately our response as we need to update its format within future requests.
        let mut working_body = response.clone();

        // We now must handle all callbacks.
        for callback in working_body.callbacks.iter_mut() {
            callback.process(&credentials);
        }

        // println!("{:?}", working_body);
        // We now make the request once more but with our adapted body.
        response = authenticate_request(&client, working_body).await;
    }
}

impl AuthenticationCallback {
    /// Process and handle all necessary inputs/outputs for this callback..
    pub fn process(&mut self, credentials: &AuthCredentials) {
        // Frustratingly, not every output has a corresponding input.
        // We'll iterate through pairs and handle as necessary.
        let callback_type = self.callback_type.as_str();
        let mut output_iter = self.output.iter_mut();
        let mut input_iter = self.input.iter_mut();

        println!("Callback type: {}", self.callback_type);

        // TODO(spotlightishere): This design is a mess with all the different types :(
        match (callback_type, output_iter.next(), input_iter.next()) {
            ("NameCallback", Some(output), Some(input)) => {
                println!("hiii");

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
                // Let's ensure that this is actually our password field.
                let prompt_name = &output.value;
                if prompt_name == "Password" {
                    input.value = json!(credentials.password);
                } else {
                    unimplemented!("unknown password callback prompt name: {}", prompt_name)
                }
            }
            ("HiddenValueCallback", _, Some(input)) => {
                // TODO: There's likely more than one possible value than `devicePrint`,
                // but this appears to be the only one handled by the SDK as of writing.
                let random_fingerprint = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
                input.value = json!(random_fingerprint);
            }
            ("ChoiceCallback", _, _) => {
                // We generally don't need to modify the defaults here.
                // TODO: Change if necessary
            }
            (_, _, _) => {
                println!("New type discovered: {}", callback_type);
                println!("{:?}", self);
                unimplemented!();
            }
        }
    }
}

/// Creates and executes the actual authentication request with the given client.
async fn authenticate_request<T: Serialize>(
    client: &reqwest::Client,
    json: T,
) -> AuthenticateFormat {
    // We'll need to serialize our text to begin with.
    let posted_contents =
        serde_json::to_string(&json).expect("should have valid JSON to POST with");
    println!("About to post: {}", posted_contents);

    // There are several necessary components to our authenticate request:
    let request = client
        .request(Method::POST, constants::AUTHENTICATE_ENDPOINT)
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
        .build()
        .expect("should be able to build authentication request");

    let result = client
        .execute(request)
        .await
        .expect("should be able to make authentication request");

    // Let's ensure that we made this request successfully.
    // We (naively) assume that any request resulting in an error
    // will have a non-200 response code.
    if !result.status().is_success() {
        // TODO(spotlightishere): Handle this better!
        println!("Hmm... something has gone awry: {:?}", result);
        panic!("Hell has frozen over");
    }

    // Finally, we can serialize to our expected format.
    let response_text = result
        .text()
        .await
        .expect("should be able to obtain authentication request body");
    println!("body: {}", response_text);

    match serde_json::from_str(response_text.as_str()) {
        Ok(body) => body,
        Err(error) => {
            println!("Encountered an error: {}", error);
            panic!("uh oh");
        }
    }
}

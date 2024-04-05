#[derive(Debug)]
pub struct ApiClient {
    /// The internal access token across API requests.
    access_token: String,
    /// The parsed GUID from the access token.
    guid: String,
}

#[derive(Debug)]
pub enum ApiError {}

impl ApiClient {
    /// Creates a new API client around the given access token and GUID.
    pub fn new(access_token: String, guid: String) -> Self {
        Self { access_token, guid }
    }
}

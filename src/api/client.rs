#[derive(Debug)]
pub struct ApiClient {
    /// The internal access token across API requests.
    access_token: String,
    /// The parsed GUID from the access token.
    guid: String,
}

#[derive(Debug)]
pub enum ApiError {
    InvalidToken,
}

impl ApiClient {
    /// Creates a new API client around the given access token.
    pub fn new(access_token: String) -> Result<Self, ApiError> {
        // TODO(spotlightishere): Handle accordingly
        Ok(Self {
            access_token: access_token,
            guid: "".to_string(),
        })
    }
}

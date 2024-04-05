mod api;
mod forgerock;

#[tokio::main]
async fn main() {
    // Before anything else, let's ensure we have the API key available.
    api::ensure_gateway_key().await;

    // We can finally initialize our API client!
    let client = forgerock::login().await.expect("should be able to log in");
    println!("{:?}", client);
}

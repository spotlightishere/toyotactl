mod api;
mod forgerock;

#[tokio::main]
async fn main() {
    let client = forgerock::login().await.expect("should be able to log in");
    println!("{:?}", client);
}

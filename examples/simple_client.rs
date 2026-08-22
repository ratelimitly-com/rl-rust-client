use std::error::Error;
use std::time::Duration;

use ratelimitly::{ApiKey, Client, Decision, Resource};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let api_key: ApiKey = std::env::var("RATELIMITLY_API_KEY")?.parse()?;
    let client = Client::builder(api_key).build().await?;
    let checkout = Resource::new("checkout", Duration::from_secs(1), 100)?;

    let response = client.request().consume(&checkout, 1)?.send().await?;
    match response.decision() {
        Decision::Granted => println!("checkout admitted"),
        Decision::Rejected => println!("checkout rejected"),
    }

    Ok(())
}

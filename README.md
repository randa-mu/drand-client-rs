# 🎲 🦀 drand-client-rs

A simple drand client implementation written in rust

## Features
- HTTP transport
- `pedersen-bls-chained` scheme
- `pedersen-bls-unchained` scheme
- `bls-unchained-on-g1` scheme
- `bls-unchained-on-g1-rfc9380` scheme

## Example usage

```rust
use drand_client_rs::{new_http_client, DrandClientError};

fn main() -> Result<(), DrandClientError> {
    // first create the client using one of the relays as a `base_url`
    let drand_client = new_http_client("https://api.drand.sh")?;

    // you can fetch the latest random value using `latest_randomness`
    if let Ok(beacon) = drand_client.latest_randomness() {
        println!("the latest round is {}", beacon.round_number);
        println!("the latest randomness is {:?}", beacon.randomness);
    }

    // or a specific round using `randomness`
    if let Ok(beacon) = drand_client.randomness(1) {
        println!("the selected round is {}", beacon.round_number);
        println!("the latest randomness is {:?}", beacon.randomness);
    }

    Ok(())
}

```


## Roadmap
- [ ] rustdoc
- [ ] wasm-specific target
- [ ] libp2p transport

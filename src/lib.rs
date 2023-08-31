extern crate core;

mod chain_info;
mod http;
mod verify;

use crate::chain_info::ChainInfo;
use crate::http::{new_http_transport, HttpTransport};
use crate::verify::{verify_beacon, Beacon};
use crate::DrandClientError::{InvalidChainInfo, InvalidRound};
use thiserror::Error;

pub struct DrandClient<'a, T: Transport> {
    transport: T,
    base_url: &'a str,
    chain_info: ChainInfo,
}

pub fn new_http_client(base_url: &str) -> Result<DrandClient<HttpTransport>, DrandClientError> {
    let http_transport = new_http_transport();
    let chain_info = fetch_chain_info(&http_transport, base_url)?;
    Ok(DrandClient {
        base_url,
        transport: http_transport,
        chain_info,
    })
}

pub trait Transport {
    fn fetch(&self, url: &str) -> Result<String, TransportError>;
}

pub fn fetch_chain_info(
    transport: &HttpTransport,
    base_url: &str,
) -> Result<ChainInfo, DrandClientError> {
    let url = format!("{base_url}/info");
    match transport.fetch(&url) {
        Err(_) => Err(DrandClientError::NotResponding),
        Ok(body) => serde_json::from_str(&body).map_err(|e| {
            println!("{}", e);
            InvalidChainInfo
        }),
    }
}

impl<'a, T: Transport> DrandClient<'a, T> {
    pub fn latest_randomness(&self) -> Result<Beacon, DrandClientError> {
        self.fetch_beacon_tag("latest")
    }

    pub fn randomness(&self, round_number: u64) -> Result<Beacon, DrandClientError> {
        if round_number == 0 {
            Err(InvalidRound)
        } else {
            self.fetch_beacon_tag(&format!("{round_number}"))
        }
    }

    fn fetch_beacon_tag(&self, tag: &str) -> Result<Beacon, DrandClientError> {
        let url = format!("{}/public/{}", self.base_url, tag);

        match self.transport.fetch(&url) {
            Err(_) => Err(DrandClientError::NotResponding),

            Ok(body) => match serde_json::from_str::<Beacon>(&body) {
                Ok(beacon) => {
                    verify_beacon(
                        &self.chain_info.scheme_id,
                        &self.chain_info.public_key,
                        &beacon,
                    )
                    .map_err(|_| DrandClientError::FailedVerification)?;
                    Ok(beacon)
                }
                Err(_) => Err(DrandClientError::InvalidBeacon),
            },
        }
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum DrandClientError {
    #[error("invalid round")]
    InvalidRound,
    #[error("invalid beacon")]
    InvalidBeacon,
    #[error("beacon failed verification")]
    FailedVerification,
    #[error("invalid chain info")]
    InvalidChainInfo,
    #[error("not responding")]
    NotResponding,
}

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("not found")]
    NotFound,
    #[error("unexpected")]
    Unexpected,
}

#[cfg(test)]
mod test {
    use crate::DrandClientError::InvalidRound;
    use crate::{new_http_client, DrandClientError};

    #[test]
    fn request_chained_randomness_success() -> Result<(), DrandClientError> {
        let chained_url = "https://api.drand.sh";
        let client = new_http_client(chained_url)?;
        let randomness = client.latest_randomness()?;
        assert!(randomness.round_number > 0);
        Ok(())
    }

    #[test]
    fn request_unchained_randomness_success() -> Result<(), DrandClientError> {
        let unchained_url = "https://pl-eu.testnet.drand.sh/7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf";
        let client = new_http_client(unchained_url)?;
        let randomness = client.latest_randomness()?;
        assert!(randomness.round_number > 0);
        Ok(())
    }

    #[test]
    fn request_genesis_returns_error() -> Result<(), DrandClientError> {
        let chained_url = "https://api.drand.sh";
        let client = new_http_client(chained_url)?;
        let result = client.randomness(0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), InvalidRound);
        Ok(())
    }

    #[test]
    fn request_g1g2swapped_beacon_succeeds() -> Result<(), DrandClientError> {
        let unchained_url =
            "https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493";
        let client = new_http_client(unchained_url)?;
        client.randomness(1)?;
        Ok(())
    }

    #[test]
    fn request_g1g2swapped_rfc_beacon_succeeds() -> Result<(), DrandClientError> {
        let unchained_url =
            "https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
        let client = new_http_client(unchained_url)?;
        client.randomness(1)?;
        Ok(())
    }

    #[test]
    fn request_g1g2swapped_rfc_latest_succeeds() -> Result<(), DrandClientError> {
        let unchained_url =
            "https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
        let client = new_http_client(unchained_url)?;
        client.latest_randomness()?;
        Ok(())
    }
}

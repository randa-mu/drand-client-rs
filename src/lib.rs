//! # drand-client-rs
//!
//! `drand_client_rs` is a small rust library for retrieving random numbers from the [drand network](https://drand.love).
//!

extern crate core;

pub mod chain_info;
pub mod http;
pub mod verify;

use crate::chain_info::ChainInfo;
use crate::http::{new_http_transport, HttpTransport};
use crate::verify::{verify_beacon, Beacon};
use crate::DrandClientError::{InvalidChainInfo, InvalidRound};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// a struct encapsulating all the necessary state for retrieving and validating drand beacons.
pub struct DrandClient<'a, T: Transport> {
    transport: T,
    base_url: &'a str,
    chain_info: ChainInfo,
}

/// create a new instance of the client with an HTTP transport for a given `base_url`.
/// Supported `base_url`s include: "<https://api.drand.sh>", "<https://drand.cloudflare.com>" and "<https://api.drand.secureweb3.com:6875>".
/// A full list can be found at <https://drand.love/developer/>
pub fn new_http_client(base_url: &str) -> Result<DrandClient<HttpTransport>, DrandClientError> {
    let http_transport = new_http_transport();
    let chain_info = fetch_chain_info(&http_transport, base_url)?;
    Ok(DrandClient {
        base_url,
        transport: http_transport,
        chain_info,
    })
}

/// represents a transport on which to connect to the drand network. This crate provides an
/// HTTP transport out of the box, which can be created by calling `new_http_transport()`
pub trait Transport {
    fn fetch(&self, url: &str) -> Result<String, TransportError>;
}

/// fetch the chain info for a given URL. The chain info contains the public key (used to
/// verify beacons) and the genesis time (used to calculate the time for given rounds).
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

/// an implementation of the logic for retrieving randomness
impl<'a, T: Transport> DrandClient<'a, T> {
    /// fetch the latest available randomness beacon
    pub fn latest_randomness(&self) -> Result<Beacon, DrandClientError> {
        let expected_round = round_for_time(&self.chain_info, SystemTime::now())?;
        let beacon = self.fetch_beacon_tag("latest")?;

        // it could take some time to aggregate beacons, so we tolerate one round early for latest
        if beacon.round_number < expected_round - 1 {
            return Err(DrandClientError::InvalidBeacon);
        }

        Ok(beacon)
    }

    /// fetch a randomness beacon for a specific round
    pub fn randomness(&self, round_number: u64) -> Result<Beacon, DrandClientError> {
        if round_number == 0 {
            Err(InvalidRound)
        } else {
            let beacon = self.fetch_beacon_tag(&format!("{round_number}"))?;
            if beacon.round_number != round_number {
                return Err(DrandClientError::InvalidBeacon);
            }
            Ok(beacon)
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

pub fn round_for_time(chain_info: &ChainInfo, time: SystemTime) -> Result<u64, DrandClientError> {
    let epoch_seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DrandClientError::UnexpectedError)?
        .as_secs();

    if epoch_seconds <= chain_info.genesis_time {
        return Err(DrandClientError::RoundBeforeGenesis);
    }

    // at genesis, the round == 1, so we add 1
    Ok((epoch_seconds - chain_info.genesis_time) / chain_info.period_seconds as u64 + 1)
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
    #[error("round before genesis")]
    RoundBeforeGenesis,
    #[error("unexpected error")]
    UnexpectedError,
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
    use crate::chain_info::{ChainInfo, ChainInfoMetadata};
    use crate::verify::SchemeID::PedersenBlsChained;
    use crate::DrandClientError::InvalidRound;
    use crate::{new_http_client, DrandClient, DrandClientError, Transport, TransportError};
    use std::time::{SystemTime, UNIX_EPOCH};

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

    #[test]
    fn request_mismatching_round_fails() -> Result<(), DrandClientError> {
        let info = ChainInfo {
            scheme_id: PedersenBlsChained,
            public_key: hex::decode("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31").unwrap(),
            chain_hash: hex::decode("8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce").unwrap(),
            group_hash: hex::decode("176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a").unwrap(),
            genesis_time: 1595431050,
            period_seconds: 30,
            metadata: ChainInfoMetadata {
                beacon_id: "default".to_string(),
            },
        };
        let beacon = "{\"round\":2,\"randomness\":\"e8fee7dac6eb2b89df97d631cfccedbada7d5d05495bb546eef462e4145fdf8f\",\"signature\":\"aa18facd2d51b616511d542de6f9af8a3b920121401dad1434ed1db4a565f10e04fad8d9b2b4e3e0094364374caafe9b10478bf75650124831509c638b5a36a7a232ec70289f8751a2adb47fc32eb70b57dc81c39d48cbcac9fec46cdfc31663\",\"previous_signature\":\"8d61d9100567de44682506aea1a7a6fa6e5491cd27a0a0ed349ef6910ac5ac20ff7bc3e09d7c046566c9f7f3c6f3b10104990e7cb424998203d8f7de586fb7fa5f60045417a432684f85093b06ca91c769f0e7ca19268375e659c2a2352b4655\"";
        let transport = MockTransport { beacon };
        let client = DrandClient {
            transport,
            base_url: "api.drand.sh",
            chain_info: info,
        };

        client
            .randomness(4)
            .expect_err("expected error for mismatching round");
        Ok(())
    }

    #[test]
    fn request_latest_round_too_far_in_past_fails() -> Result<(), DrandClientError> {
        let info = ChainInfo {
            scheme_id: PedersenBlsChained,
            public_key: hex::decode("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31").unwrap(),
            chain_hash: hex::decode("8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce").unwrap(),
            group_hash: hex::decode("176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a").unwrap(),
            genesis_time: 1595431050,
            period_seconds: 30,
            metadata: ChainInfoMetadata {
                beacon_id: "default".to_string(),
            },
        };
        let beacon = "{\"round\":2,\"randomness\":\"e8fee7dac6eb2b89df97d631cfccedbada7d5d05495bb546eef462e4145fdf8f\",\"signature\":\"aa18facd2d51b616511d542de6f9af8a3b920121401dad1434ed1db4a565f10e04fad8d9b2b4e3e0094364374caafe9b10478bf75650124831509c638b5a36a7a232ec70289f8751a2adb47fc32eb70b57dc81c39d48cbcac9fec46cdfc31663\",\"previous_signature\":\"8d61d9100567de44682506aea1a7a6fa6e5491cd27a0a0ed349ef6910ac5ac20ff7bc3e09d7c046566c9f7f3c6f3b10104990e7cb424998203d8f7de586fb7fa5f60045417a432684f85093b06ca91c769f0e7ca19268375e659c2a2352b4655\"";
        let transport = MockTransport { beacon };
        let client = DrandClient {
            transport,
            base_url: "api.drand.sh",
            chain_info: info,
        };

        client
            .latest_randomness()
            .expect_err("expected error for mismatching round");
        Ok(())
    }

    #[test]
    fn request_latest_single_round_early_succeeds() -> Result<(), DrandClientError> {
        let info = ChainInfo {
            scheme_id: PedersenBlsChained,
            public_key: hex::decode("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31").unwrap(),
            chain_hash: hex::decode("8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce").unwrap(),
            group_hash: hex::decode("176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a").unwrap(),
            // here we set genesis so it should be round 3
            genesis_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 60,
            period_seconds: 30,
            metadata: ChainInfoMetadata {
                beacon_id: "default".to_string(),
            },
        };
        let beacon = "{\"round\":2,\"randomness\":\"e8fee7dac6eb2b89df97d631cfccedbada7d5d05495bb546eef462e4145fdf8f\",\"signature\":\"aa18facd2d51b616511d542de6f9af8a3b920121401dad1434ed1db4a565f10e04fad8d9b2b4e3e0094364374caafe9b10478bf75650124831509c638b5a36a7a232ec70289f8751a2adb47fc32eb70b57dc81c39d48cbcac9fec46cdfc31663\",\"previous_signature\":\"8d61d9100567de44682506aea1a7a6fa6e5491cd27a0a0ed349ef6910ac5ac20ff7bc3e09d7c046566c9f7f3c6f3b10104990e7cb424998203d8f7de586fb7fa5f60045417a432684f85093b06ca91c769f0e7ca19268375e659c2a2352b4655\"}";
        let transport = MockTransport { beacon };
        let client = DrandClient {
            transport,
            base_url: "api.drand.sh",
            chain_info: info,
        };

        client
            .latest_randomness()
            .expect("beacon should be returned successfully");
        Ok(())
    }

    #[test]
    fn request_latest_future_round_succeeds() -> Result<(), DrandClientError> {
        let info = ChainInfo {
            scheme_id: PedersenBlsChained,
            public_key: hex::decode("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31").unwrap(),
            chain_hash: hex::decode("8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce").unwrap(),
            group_hash: hex::decode("176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a").unwrap(),
            genesis_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 30,
            period_seconds: 30,
            metadata: ChainInfoMetadata {
                beacon_id: "default".to_string(),
            },
        };
        let beacon = "{\"round\":2,\"randomness\":\"e8fee7dac6eb2b89df97d631cfccedbada7d5d05495bb546eef462e4145fdf8f\",\"signature\":\"aa18facd2d51b616511d542de6f9af8a3b920121401dad1434ed1db4a565f10e04fad8d9b2b4e3e0094364374caafe9b10478bf75650124831509c638b5a36a7a232ec70289f8751a2adb47fc32eb70b57dc81c39d48cbcac9fec46cdfc31663\",\"previous_signature\":\"8d61d9100567de44682506aea1a7a6fa6e5491cd27a0a0ed349ef6910ac5ac20ff7bc3e09d7c046566c9f7f3c6f3b10104990e7cb424998203d8f7de586fb7fa5f60045417a432684f85093b06ca91c769f0e7ca19268375e659c2a2352b4655\"}";
        let transport = MockTransport { beacon };
        let client = DrandClient {
            transport,
            base_url: "api.drand.sh",
            chain_info: info,
        };

        client
            .latest_randomness()
            .expect("beacon should be returned successfully");
        Ok(())
    }

    struct MockTransport<'a> {
        beacon: &'a str,
    }

    impl Transport for MockTransport<'_> {
        fn fetch(&self, _: &str) -> Result<String, TransportError> {
            Ok(self.beacon.to_string())
        }
    }
}

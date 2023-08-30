use crate::verify::SchemeID;
use serde::Deserialize;

#[derive(Deserialize, Debug, PartialEq, Clone)]
pub struct ChainInfo {
    #[serde(alias = "schemeID")]
    pub scheme_id: SchemeID,
    #[serde(with = "hex")]
    pub public_key: Vec<u8>,
    #[serde(with = "hex", alias = "hash")]
    pub chain_hash: Vec<u8>,
    #[serde(with = "hex", alias = "groupHash")]
    pub group_hash: Vec<u8>,
    pub genesis_time: u64,
    #[serde(alias = "period")]
    pub period_seconds: usize,
    pub metadata: ChainInfoMetadata,
}

#[derive(Deserialize, Debug, PartialEq, Clone)]
pub struct ChainInfoMetadata {
    #[serde(alias = "beaconID")]
    pub beacon_id: String,
}

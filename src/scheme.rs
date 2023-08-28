use sha2::{Digest, Sha256};
use serde::{Deserialize, Deserializer};
use crate::verify::{verify_on_g1, verify_on_g2};

#[derive(Deserialize, Debug, PartialEq, Clone)]
pub struct Beacon {
    #[serde(alias = "round")]
    pub round_number: u64,
    #[serde(with = "hex")]
    pub randomness: Vec<u8>,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
    #[serde(default, with = "hex")]
    pub previous_signature: Vec<u8>,
}

const DST_G1: &str = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
const DST_G2: &str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

#[derive(Debug, PartialEq, Clone)]
pub enum SchemeID {
    PedersenBlsChained,
    PedersenBlsUnchained,
    UnchainedOnG1,
    UnchainedOnG1RFC9380,
}

impl<'de> Deserialize<'de> for SchemeID {
    fn deserialize<D>(deserializer: D) -> Result<SchemeID, D::Error>
        where
            D: Deserializer<'de>,
    {
        let s = Deserialize::deserialize(deserializer)?;
        match s {
            "pedersen-bls-chained" => Ok(SchemeID::PedersenBlsChained),
            "pedersen-bls-unchained" => Ok(SchemeID::PedersenBlsUnchained),
            "bls-unchained-on-g1" => Ok(SchemeID::UnchainedOnG1),
            "bls-unchained-g1-rfc9380" => Ok(SchemeID::UnchainedOnG1RFC9380),
            _ => Err(serde::de::Error::unknown_variant(&s, &["pedersen-bls-chained", "pedersen-bls-unchained", "bls-unchained-on-g1", "bls-unchained-g1-rfc9380"]))
        }
    }
}

pub fn verify_beacon<'a>(scheme_id: &SchemeID, public_key: &[u8], beacon: &'a Beacon) -> Result<(), &'a str> {
    match scheme_id {
        SchemeID::PedersenBlsChained =>
            verify_on_g2(public_key, &chained_beacon_message(beacon)?, &beacon.signature, DST_G2),
        SchemeID::PedersenBlsUnchained =>
            verify_on_g2(public_key, &unchained_beacon_message(beacon)?, &beacon.signature, DST_G2),
        SchemeID::UnchainedOnG1 =>
            verify_on_g1(public_key, &unchained_beacon_message(beacon)?, &beacon.signature, DST_G2),
        SchemeID::UnchainedOnG1RFC9380 =>
            verify_on_g1(public_key, &unchained_beacon_message(beacon)?, &beacon.signature, DST_G1),
    }
}

fn unchained_beacon_message<'a>(beacon: &Beacon) -> Result<Vec<u8>, &'a str> {
    if beacon.previous_signature.len() > 0 {
        return Err("unchained schemes cannot contain a `previous_signature`");
    }
    let round_bytes = beacon.round_number.to_be_bytes();

    Ok(Sha256::digest(&round_bytes).to_vec())
}

fn chained_beacon_message<'a>(beacon: &Beacon) -> Result<Vec<u8>, &'a str> {
    if beacon.previous_signature.len() == 0 {
        Err("chained beacons must have a `previous_signature`")
    } else {
        // surely there's a better way to concat two slices
        let mut message = Vec::new();
        message.extend_from_slice(&beacon.previous_signature.as_slice());
        message.extend_from_slice(&beacon.round_number.to_be_bytes());
        Ok(Sha256::digest(message.as_slice()).to_vec())
    }
}

#[cfg(test)]
mod test {
    use crate::scheme::{Beacon, SchemeID, verify_beacon};

    #[test]
    fn default_beacon_verifies() {
        let public_key = hexify("88a8227b75dba145599d894d33eebde3b36fef900d456ae2cc4388867adb4769c40359f783750a41b4d17e40f578bfdb");
        let prev_sig = hexify("a2237ee39a1a6569cb8e02c6e979c07efe1f30be0ac501436bd325015f1cd6129dc56fd60efcdf9158d74ebfa34bfcbd17803dbca6d2ae8bc3a968e4dc582f8710c69de80b2e649663fef5742d22fff7d1619b75d5f222e8c9b8840bc2044bce");

        let beacon = Beacon {
            round_number: 397089,
            randomness: hexify("cd435675735e459fb4d9c68a9d9f7b719e59e0a9f5f86fe6bd86b730d01fba42"),
            signature: hexify("88ccd9a91946bc0bbef2c6c60a09bbf4a247b1d2059522449aa1a35758feddfad85efe818bbde3e1e4ab0c852d96e65f0b1f97f239bf3fc918860ea846cbb500fcf7c9d0dd3d851320374460b5fc596b8cfd629f4c07c7507c259bf9beca850a"),
            previous_signature: prev_sig,
        };

        assert!(matches!(verify_beacon(&SchemeID::PedersenBlsChained, &public_key, &beacon), Ok(())));
    }

    #[test]
    fn testnet_unchained_beacon_verifies() {
        let public_key = hexify("8d91ae0f4e3cd277cfc46aba26680232b0d5bb4444602cdb23442d62e17f43cdffb1104909e535430c10a6a1ce680a65");
        let beacon = Beacon {
            round_number: 397092,
            randomness: hexify("7731783ab8118d7484d0e8e237f3023a4c7ef4532f35016f2e56e89a7570c796"),
            signature: hexify("94da96b5b985a22a3d99fa3051a42feb4da9218763f6c836fca3770292dbf4b01f5d378859a113960548d167eaa144250a2c8e34c51c5270152ac2bc7a52632236f746545e0fae52f69068c017745204240d19dae2b4d038cef3c6047fcd6539"),
            previous_signature: Vec::new(),
        };

        assert!(matches!(verify_beacon(&SchemeID::PedersenBlsUnchained, &public_key, &beacon), Ok(_)));
    }

    #[test]
    fn g1g2_swap_non_rfc_beacon_verifies() {
        let public_key = hexify("a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e");
        let beacon = Beacon {
            round_number: 3,
            randomness: hexify("a4eb0ed6c4132da066843c3bfdce732ce5013eda86e74c136ab8ccc387b798dd"),
            signature: hexify("8176555f90d71aa49ceb37739683749491c2bab15a46094b255289ed25cf8f01cdfb1fe8bd9cd5a19eb09448a3e53186"),
            previous_signature: Vec::new(),
        };

        assert!(matches!(verify_beacon(&SchemeID::UnchainedOnG1, &public_key, &beacon), Ok(_)));
    }

    #[test]
    fn g1g2_swap_rfc_beacon_verifies() {
        let public_key = hexify("83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a");
        let beacon = Beacon {
            round_number: 1000,
            randomness: hexify("fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd"),
            signature: hexify("b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"),
            previous_signature: Vec::new(),
        };

        assert!(matches!(verify_beacon(&SchemeID::UnchainedOnG1RFC9380, &public_key, &beacon), Ok(_)));
    }

    fn hexify(s: &str) -> Vec<u8> {
        return hex::decode(s)
            .unwrap()
            .to_vec();
    }
}

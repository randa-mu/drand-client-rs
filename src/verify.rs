use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt,
};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use std::ops::Neg;
use thiserror::Error;

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
            _ => Err(serde::de::Error::unknown_variant(
                s,
                &[
                    "pedersen-bls-chained",
                    "pedersen-bls-unchained",
                    "bls-unchained-on-g1",
                    "bls-unchained-g1-rfc9380",
                ],
            )),
        }
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum VerificationError {
    #[error("chained beacons must have a `previous_signature`")]
    ChainedBeaconNeedsPreviousSignature,
    #[error("invalid signature length")]
    InvalidSignatureLength,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("message can't be empty")]
    EmptyMessage,
    #[error("signature verification failed")]
    SignatureFailedVerification,
    #[error("the randomness for the beacon did not match the signature")]
    InvalidRandomness,
}

pub fn verify_beacon(
    scheme_id: &SchemeID,
    public_key: &[u8],
    beacon: &Beacon,
) -> Result<(), VerificationError> {
    if Sha256::digest(&beacon.signature).to_vec() != beacon.randomness {
        return Err(VerificationError::InvalidRandomness);
    }
    match scheme_id {
        SchemeID::PedersenBlsChained => verify_on_g2(
            public_key,
            &chained_beacon_message(beacon)?,
            &beacon.signature,
            DST_G2,
        ),
        SchemeID::PedersenBlsUnchained => verify_on_g2(
            public_key,
            &unchained_beacon_message(beacon)?,
            &beacon.signature,
            DST_G2,
        ),
        SchemeID::UnchainedOnG1 => verify_on_g1(
            public_key,
            &unchained_beacon_message(beacon)?,
            &beacon.signature,
            DST_G2,
        ),
        SchemeID::UnchainedOnG1RFC9380 => verify_on_g1(
            public_key,
            &unchained_beacon_message(beacon)?,
            &beacon.signature,
            DST_G1,
        ),
    }
}

fn unchained_beacon_message(beacon: &Beacon) -> Result<Vec<u8>, VerificationError> {
    let round_bytes = beacon.round_number.to_be_bytes();

    Ok(Sha256::digest(&round_bytes).to_vec())
}

fn chained_beacon_message(beacon: &Beacon) -> Result<Vec<u8>, VerificationError> {
    if beacon.previous_signature.is_empty() {
        Err(VerificationError::ChainedBeaconNeedsPreviousSignature)
    } else {
        let message: Vec<u8> = beacon
            .previous_signature
            .clone()
            .into_iter()
            .chain(beacon.round_number.to_be_bytes())
            .collect();

        Ok(Sha256::digest(message.as_slice()).to_vec())
    }
}

pub fn verify_on_g2(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    domain_separation_tag: &str,
) -> Result<(), VerificationError> {
    let pub_key_bytes: &[u8; 48] = public_key
        .try_into()
        .map_err(|_| VerificationError::InvalidPublicKey)?;

    let sig_bytes: &[u8; 96] = signature
        .try_into()
        .map_err(|_| VerificationError::InvalidSignatureLength)?;

    let p = G1Affine::from_compressed(pub_key_bytes).unwrap_or(G1Affine::identity());

    let q = G2Affine::from_compressed(sig_bytes).unwrap_or(G2Affine::identity());

    if p.is_on_curve().unwrap_u8() != 1 {
        return Err(VerificationError::InvalidPublicKey);
    }

    if p.is_identity().unwrap_u8() == 1 {
        return Err(VerificationError::InvalidPublicKey);
    }

    if message.is_empty() {
        return Err(VerificationError::EmptyMessage);
    }

    if signature.is_empty() {
        return Err(VerificationError::InvalidSignatureLength);
    }

    let m = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        message,
        domain_separation_tag.as_bytes(),
    );

    let m_prepared = G2Prepared::from(G2Affine::from(m));
    let q_prepared = G2Prepared::from(q);
    let exp = multi_miller_loop(&[
        (&p.neg(), &m_prepared),
        (&G1Affine::generator(), &q_prepared),
    ]);

    if exp.final_exponentiation() != Gt::identity() {
        Err(VerificationError::SignatureFailedVerification)
    } else {
        Ok(())
    }
}

pub fn verify_on_g1(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    domain_separation_tag: &str,
) -> Result<(), VerificationError> {
    let pub_key_bytes: &[u8; 96] = public_key
        .try_into()
        .map_err(|_| VerificationError::InvalidPublicKey)?;

    let sig_bytes: &[u8; 48] = signature
        .try_into()
        .map_err(|_| VerificationError::InvalidSignatureLength)?;

    let signature_point = G1Affine::from_compressed(sig_bytes).unwrap_or(G1Affine::identity());
    let pubkey_point = G2Affine::from_compressed(pub_key_bytes).unwrap_or(G2Affine::identity());

    if pubkey_point.is_on_curve().unwrap_u8() != 1 {
        return Err(VerificationError::InvalidPublicKey);
    }

    if pubkey_point.is_identity().unwrap_u8() == 1 {
        return Err(VerificationError::InvalidPublicKey);
    }

    if message.is_empty() {
        return Err(VerificationError::EmptyMessage);
    }

    if signature.is_empty() {
        return Err(VerificationError::InvalidSignatureLength);
    }

    let m = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        message,
        domain_separation_tag.as_bytes(),
    );

    let pubkey_prepared = G2Prepared::from(pubkey_point.neg());
    let g2_base = G2Prepared::from(G2Affine::generator());
    let exp = multi_miller_loop(&[
        (&G1Affine::from(m), &pubkey_prepared),
        (&signature_point, &g2_base),
    ]);

    if exp.final_exponentiation() != Gt::identity() {
        Err(VerificationError::SignatureFailedVerification)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::verify::{verify_beacon, Beacon, SchemeID, VerificationError};
    use bls12_381::{G1Affine, G2Affine};

    #[test]
    fn default_beacon_verifies() {
        let public_key = dehexify("88a8227b75dba145599d894d33eebde3b36fef900d456ae2cc4388867adb4769c40359f783750a41b4d17e40f578bfdb");
        let prev_sig = dehexify("a2237ee39a1a6569cb8e02c6e979c07efe1f30be0ac501436bd325015f1cd6129dc56fd60efcdf9158d74ebfa34bfcbd17803dbca6d2ae8bc3a968e4dc582f8710c69de80b2e649663fef5742d22fff7d1619b75d5f222e8c9b8840bc2044bce");

        let beacon = Beacon {
            round_number: 397089,
            randomness: dehexify("cd435675735e459fb4d9c68a9d9f7b719e59e0a9f5f86fe6bd86b730d01fba42"),
            signature: dehexify("88ccd9a91946bc0bbef2c6c60a09bbf4a247b1d2059522449aa1a35758feddfad85efe818bbde3e1e4ab0c852d96e65f0b1f97f239bf3fc918860ea846cbb500fcf7c9d0dd3d851320374460b5fc596b8cfd629f4c07c7507c259bf9beca850a"),
            previous_signature: prev_sig,
        };

        assert!(matches!(
            verify_beacon(&SchemeID::PedersenBlsChained, &public_key, &beacon),
            Ok(()),
        ));
    }

    #[test]
    fn default_wrong_round_fails() {
        let public_key = dehexify("88a8227b75dba145599d894d33eebde3b36fef900d456ae2cc4388867adb4769c40359f783750a41b4d17e40f578bfdb");
        let prev_sig = dehexify("a2237ee39a1a6569cb8e02c6e979c07efe1f30be0ac501436bd325015f1cd6129dc56fd60efcdf9158d74ebfa34bfcbd17803dbca6d2ae8bc3a968e4dc582f8710c69de80b2e649663fef5742d22fff7d1619b75d5f222e8c9b8840bc2044bce");

        let beacon = Beacon {
            round_number: 1, // wrong round for randomness
            randomness: dehexify("cd435675735e459fb4d9c68a9d9f7b719e59e0a9f5f86fe6bd86b730d01fba42"),
            signature: dehexify("88ccd9a91946bc0bbef2c6c60a09bbf4a247b1d2059522449aa1a35758feddfad85efe818bbde3e1e4ab0c852d96e65f0b1f97f239bf3fc918860ea846cbb500fcf7c9d0dd3d851320374460b5fc596b8cfd629f4c07c7507c259bf9beca850a"),
            previous_signature: prev_sig,
        };

        assert_error(
            verify_beacon(&SchemeID::PedersenBlsChained, &public_key, &beacon),
            VerificationError::SignatureFailedVerification,
        );
    }

    #[test]
    fn default_with_invalid_randomness_fails() {
        let public_key = dehexify("88a8227b75dba145599d894d33eebde3b36fef900d456ae2cc4388867adb4769c40359f783750a41b4d17e40f578bfdb");
        let prev_sig = dehexify("a2237ee39a1a6569cb8e02c6e979c07efe1f30be0ac501436bd325015f1cd6129dc56fd60efcdf9158d74ebfa34bfcbd17803dbca6d2ae8bc3a968e4dc582f8710c69de80b2e649663fef5742d22fff7d1619b75d5f222e8c9b8840bc2044bce");

        let beacon = Beacon {
            round_number: 397089,
            // updated the randomness hex to be wrong
            randomness: dehexify("bd435675735e459fb4d9c68a9d9f7b719e59e0a9f5f86fe6bd86b730d01fba42"),
            signature: dehexify("88ccd9a91946bc0bbef2c6c60a09bbf4a247b1d2059522449aa1a35758feddfad85efe818bbde3e1e4ab0c852d96e65f0b1f97f239bf3fc918860ea846cbb500fcf7c9d0dd3d851320374460b5fc596b8cfd629f4c07c7507c259bf9beca850a"),
            previous_signature: prev_sig,
        };

        assert_error(
            verify_beacon(&SchemeID::PedersenBlsChained, &public_key, &beacon),
            VerificationError::InvalidRandomness,
        );
    }

    #[test]
    fn default_beacon_missing_previous_sig_fails() {
        let public_key = dehexify("88a8227b75dba145599d894d33eebde3b36fef900d456ae2cc4388867adb4769c40359f783750a41b4d17e40f578bfdb");

        let beacon = Beacon {
            round_number: 397089,
            randomness: dehexify("cd435675735e459fb4d9c68a9d9f7b719e59e0a9f5f86fe6bd86b730d01fba42"),
            signature: dehexify("88ccd9a91946bc0bbef2c6c60a09bbf4a247b1d2059522449aa1a35758feddfad85efe818bbde3e1e4ab0c852d96e65f0b1f97f239bf3fc918860ea846cbb500fcf7c9d0dd3d851320374460b5fc596b8cfd629f4c07c7507c259bf9beca850a"),
            previous_signature: Vec::new(),
        };

        assert_error(
            verify_beacon(&SchemeID::PedersenBlsChained, &public_key, &beacon),
            VerificationError::ChainedBeaconNeedsPreviousSignature,
        );
    }

    #[test]
    fn default_beacon_invalid_public_key_fails() {
        // public key is not correct
        let public_key = dehexify("78a8227b75dba145599d894d33eebde3b36fef900d456ae2cc4388867adb4769c40359f783750a41b4d17e40f578bfdb");
        let prev_sig = dehexify("a2237ee39a1a6569cb8e02c6e979c07efe1f30be0ac501436bd325015f1cd6129dc56fd60efcdf9158d74ebfa34bfcbd17803dbca6d2ae8bc3a968e4dc582f8710c69de80b2e649663fef5742d22fff7d1619b75d5f222e8c9b8840bc2044bce");

        let beacon = Beacon {
            round_number: 397089,
            randomness: dehexify("cd435675735e459fb4d9c68a9d9f7b719e59e0a9f5f86fe6bd86b730d01fba42"),
            signature: dehexify("88ccd9a91946bc0bbef2c6c60a09bbf4a247b1d2059522449aa1a35758feddfad85efe818bbde3e1e4ab0c852d96e65f0b1f97f239bf3fc918860ea846cbb500fcf7c9d0dd3d851320374460b5fc596b8cfd629f4c07c7507c259bf9beca850a"),
            previous_signature: prev_sig,
        };

        assert_error(
            verify_beacon(&SchemeID::PedersenBlsChained, &public_key, &beacon),
            VerificationError::InvalidPublicKey,
        );
    }

    #[test]
    fn default_beacon_empty_public_key_fails() {
        let public_key = Vec::new();
        let prev_sig = dehexify("a2237ee39a1a6569cb8e02c6e979c07efe1f30be0ac501436bd325015f1cd6129dc56fd60efcdf9158d74ebfa34bfcbd17803dbca6d2ae8bc3a968e4dc582f8710c69de80b2e649663fef5742d22fff7d1619b75d5f222e8c9b8840bc2044bce");

        let beacon = Beacon {
            round_number: 397089,
            randomness: dehexify("cd435675735e459fb4d9c68a9d9f7b719e59e0a9f5f86fe6bd86b730d01fba42"),
            signature: dehexify("88ccd9a91946bc0bbef2c6c60a09bbf4a247b1d2059522449aa1a35758feddfad85efe818bbde3e1e4ab0c852d96e65f0b1f97f239bf3fc918860ea846cbb500fcf7c9d0dd3d851320374460b5fc596b8cfd629f4c07c7507c259bf9beca850a"),
            previous_signature: prev_sig,
        };

        assert_error(
            verify_beacon(&SchemeID::PedersenBlsChained, &public_key, &beacon),
            VerificationError::InvalidPublicKey,
        );
    }

    #[test]
    fn default_beacon_infinity_public_key_fails() {
        let public_key = G1Affine::identity().to_compressed();
        let prev_sig = dehexify("a2237ee39a1a6569cb8e02c6e979c07efe1f30be0ac501436bd325015f1cd6129dc56fd60efcdf9158d74ebfa34bfcbd17803dbca6d2ae8bc3a968e4dc582f8710c69de80b2e649663fef5742d22fff7d1619b75d5f222e8c9b8840bc2044bce");

        let beacon = Beacon {
            round_number: 397089,
            randomness: dehexify("cd435675735e459fb4d9c68a9d9f7b719e59e0a9f5f86fe6bd86b730d01fba42"),
            signature: dehexify("88ccd9a91946bc0bbef2c6c60a09bbf4a247b1d2059522449aa1a35758feddfad85efe818bbde3e1e4ab0c852d96e65f0b1f97f239bf3fc918860ea846cbb500fcf7c9d0dd3d851320374460b5fc596b8cfd629f4c07c7507c259bf9beca850a"),
            previous_signature: prev_sig,
        };

        assert_error(
            verify_beacon(&SchemeID::PedersenBlsChained, &public_key, &beacon),
            VerificationError::InvalidPublicKey,
        );
    }

    #[test]
    fn testnet_unchained_beacon_verifies() {
        let public_key = dehexify("8d91ae0f4e3cd277cfc46aba26680232b0d5bb4444602cdb23442d62e17f43cdffb1104909e535430c10a6a1ce680a65");
        let beacon = Beacon {
            round_number: 397092,
            randomness: dehexify("7731783ab8118d7484d0e8e237f3023a4c7ef4532f35016f2e56e89a7570c796"),
            signature: dehexify("94da96b5b985a22a3d99fa3051a42feb4da9218763f6c836fca3770292dbf4b01f5d378859a113960548d167eaa144250a2c8e34c51c5270152ac2bc7a52632236f746545e0fae52f69068c017745204240d19dae2b4d038cef3c6047fcd6539"),
            previous_signature: Vec::new(),
        };

        assert!(matches!(
            verify_beacon(&SchemeID::PedersenBlsUnchained, &public_key, &beacon),
            Ok(_),
        ));
    }

    #[test]
    fn testnet_unchained_beacon_wrong_round_fails() {
        let public_key = dehexify("8d91ae0f4e3cd277cfc46aba26680232b0d5bb4444602cdb23442d62e17f43cdffb1104909e535430c10a6a1ce680a65");
        let beacon = Beacon {
            round_number: 1, // wrong round
            randomness: dehexify("7731783ab8118d7484d0e8e237f3023a4c7ef4532f35016f2e56e89a7570c796"),
            signature: dehexify("94da96b5b985a22a3d99fa3051a42feb4da9218763f6c836fca3770292dbf4b01f5d378859a113960548d167eaa144250a2c8e34c51c5270152ac2bc7a52632236f746545e0fae52f69068c017745204240d19dae2b4d038cef3c6047fcd6539"),
            previous_signature: Vec::new(),
        };

        assert_error(
            verify_beacon(&SchemeID::PedersenBlsUnchained, &public_key, &beacon),
            VerificationError::SignatureFailedVerification,
        );
    }

    #[test]
    fn testnet_unchained_beacon_randomness_not_matching_signature_fails() {
        let public_key = dehexify("8d91ae0f4e3cd277cfc46aba26680232b0d5bb4444602cdb23442d62e17f43cdffb1104909e535430c10a6a1ce680a65");
        let beacon = Beacon {
            round_number: 397092,
            // mismatching randomness
            randomness: dehexify("a731783ab8118d7484d0e8e237f3023a4c7ef4532f35016f2e56e89a7570c796"),
            signature: dehexify("94da96b5b985a22a3d99fa3051a42feb4da9218763f6c836fca3770292dbf4b01f5d378859a113960548d167eaa144250a2c8e34c51c5270152ac2bc7a52632236f746545e0fae52f69068c017745204240d19dae2b4d038cef3c6047fcd6539"),
            previous_signature: Vec::new(),
        };

        assert_error(
            verify_beacon(&SchemeID::PedersenBlsUnchained, &public_key, &beacon),
            VerificationError::InvalidRandomness,
        );
    }

    #[test]
    fn testnet_unchained_beacon_containing_previous_sig_ignores_previous_sig() {
        let public_key = dehexify("8d91ae0f4e3cd277cfc46aba26680232b0d5bb4444602cdb23442d62e17f43cdffb1104909e535430c10a6a1ce680a65");
        let beacon = Beacon {
            round_number: 397092,
            randomness: dehexify("7731783ab8118d7484d0e8e237f3023a4c7ef4532f35016f2e56e89a7570c796"),
            signature: dehexify("94da96b5b985a22a3d99fa3051a42feb4da9218763f6c836fca3770292dbf4b01f5d378859a113960548d167eaa144250a2c8e34c51c5270152ac2bc7a52632236f746545e0fae52f69068c017745204240d19dae2b4d038cef3c6047fcd6539"),
            previous_signature: dehexify("94da96b5b985a22a3d99fa3051a42feb4da9218763f6c836fca3770292dbf4b01f5d378859a113960548d167eaa144250a2c8e34c51c5270152ac2bc7a52632236f746545e0fae52f69068c017745204240d19dae2b4d038cef3c6047fcd6539"),
        };

        assert!(matches!(
            verify_beacon(&SchemeID::PedersenBlsUnchained, &public_key, &beacon),
            Ok(())
        ));
    }

    #[test]
    fn testnet_unchained_invalid_public_key_fails() {
        // valid public key, but for wrong scheme
        let public_key = dehexify("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31");
        let beacon = Beacon {
            round_number: 397092,
            randomness: dehexify("7731783ab8118d7484d0e8e237f3023a4c7ef4532f35016f2e56e89a7570c796"),
            signature: dehexify("94da96b5b985a22a3d99fa3051a42feb4da9218763f6c836fca3770292dbf4b01f5d378859a113960548d167eaa144250a2c8e34c51c5270152ac2bc7a52632236f746545e0fae52f69068c017745204240d19dae2b4d038cef3c6047fcd6539"),
            previous_signature: Vec::new(),
        };

        assert_error(
            verify_beacon(&SchemeID::PedersenBlsUnchained, &public_key, &beacon),
            VerificationError::SignatureFailedVerification,
        );
    }

    #[test]
    fn testnet_unchained_beacon_empty_public_key_fails() {
        let public_key = Vec::new();
        let beacon = Beacon {
            round_number: 397092,
            randomness: dehexify("7731783ab8118d7484d0e8e237f3023a4c7ef4532f35016f2e56e89a7570c796"),
            signature: dehexify("94da96b5b985a22a3d99fa3051a42feb4da9218763f6c836fca3770292dbf4b01f5d378859a113960548d167eaa144250a2c8e34c51c5270152ac2bc7a52632236f746545e0fae52f69068c017745204240d19dae2b4d038cef3c6047fcd6539"),
            previous_signature: Vec::new(),
        };

        assert_error(
            verify_beacon(&SchemeID::PedersenBlsUnchained, &public_key, &beacon),
            VerificationError::InvalidPublicKey,
        );
    }

    #[test]
    fn testnet_unchained_beacon_infinity_public_key_fails() {
        let public_key = G2Affine::identity().to_uncompressed();
        let beacon = Beacon {
            round_number: 397092,
            randomness: dehexify("7731783ab8118d7484d0e8e237f3023a4c7ef4532f35016f2e56e89a7570c796"),
            signature: dehexify("94da96b5b985a22a3d99fa3051a42feb4da9218763f6c836fca3770292dbf4b01f5d378859a113960548d167eaa144250a2c8e34c51c5270152ac2bc7a52632236f746545e0fae52f69068c017745204240d19dae2b4d038cef3c6047fcd6539"),
            previous_signature: Vec::new(),
        };

        assert_error(
            verify_beacon(&SchemeID::PedersenBlsUnchained, &public_key, &beacon),
            VerificationError::InvalidPublicKey,
        );
    }

    #[test]
    fn g1g2_swap_non_rfc_beacon_verifies() {
        let public_key = dehexify("a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e");
        let beacon = Beacon {
            round_number: 3,
            randomness: dehexify("a4eb0ed6c4132da066843c3bfdce732ce5013eda86e74c136ab8ccc387b798dd"),
            signature: dehexify("8176555f90d71aa49ceb37739683749491c2bab15a46094b255289ed25cf8f01cdfb1fe8bd9cd5a19eb09448a3e53186"),
            previous_signature: Vec::new(),
        };

        assert!(matches!(
            verify_beacon(&SchemeID::UnchainedOnG1, &public_key, &beacon),
            Ok(_)
        ));
    }

    #[test]
    fn g1g2_swap_rfc_beacon_verifies() {
        let public_key = dehexify("83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a");
        let beacon = Beacon {
            round_number: 1000,
            randomness: dehexify("fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd"),
            signature: dehexify("b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"),
            previous_signature: Vec::new(),
        };

        assert!(matches!(
            verify_beacon(&SchemeID::UnchainedOnG1RFC9380, &public_key, &beacon),
            Ok(_)
        ));
    }

    #[test]
    fn g1g2_swap_empty_public_key_fails() {
        let public_key = Vec::new();
        let beacon = Beacon {
            round_number: 1000,
            randomness: dehexify("fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd"),
            signature: dehexify("b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"),
            previous_signature: Vec::new(),
        };

        assert_error(
            verify_beacon(&SchemeID::UnchainedOnG1RFC9380, &public_key, &beacon),
            VerificationError::InvalidPublicKey,
        );
    }

    #[test]
    fn g1g2_swap_infinity_public_key_fails() {
        let public_key = G2Affine::identity().to_uncompressed();
        let beacon = Beacon {
            round_number: 1000,
            randomness: dehexify("fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd"),
            signature: dehexify("b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"),
            previous_signature: Vec::new(),
        };

        assert_error(
            verify_beacon(&SchemeID::UnchainedOnG1RFC9380, &public_key, &beacon),
            VerificationError::InvalidPublicKey,
        );
    }

    #[test]
    fn g1g2_swap_wrong_round_fails() {
        let public_key = dehexify("83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a");
        let beacon = Beacon {
            round_number: 1,
            randomness: dehexify("fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd"),
            signature: dehexify("b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"),
            previous_signature: Vec::new(),
        };

        assert_error(
            verify_beacon(&SchemeID::UnchainedOnG1RFC9380, &public_key, &beacon),
            VerificationError::SignatureFailedVerification,
        );
    }

    #[test]
    fn g1g2_swap_invalid_randomness_fails() {
        let public_key = dehexify("83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a");
        let beacon = Beacon {
            round_number: 1000,
            // incorrect hash for the signature
            randomness: dehexify("aa290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd"),
            signature: dehexify("b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"),
            previous_signature: Vec::new(),
        };

        assert_error(
            verify_beacon(&SchemeID::UnchainedOnG1RFC9380, &public_key, &beacon),
            VerificationError::InvalidRandomness,
        );
    }

    #[test]
    fn g1g2_swap_invalid_signature_fails() {
        let public_key = dehexify("83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a");
        let beacon = Beacon {
            round_number: 1000,
            // this is not a valid signature
            signature: dehexify("a44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"),
            // but the hash matches it
            randomness: dehexify("5993706587c56d4e7079d175bfa5d52295694896e68c691b93765242096c9fa7"),
            previous_signature: Vec::new(),
        };

        assert_error(
            verify_beacon(&SchemeID::UnchainedOnG1RFC9380, &public_key, &beacon),
            VerificationError::SignatureFailedVerification,
        );
    }

    fn dehexify(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap().to_vec()
    }

    fn assert_error(actual: Result<(), VerificationError>, expected: VerificationError) {
        match actual {
            Ok(_) => panic!("expected error but got success"),
            Err(e) => {
                if e != expected {
                    panic!("expected {expected:?} but got {e:?}");
                }
            }
        }
    }
}

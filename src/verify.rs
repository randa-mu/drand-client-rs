use std::ops::{Neg};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, multi_miller_loop};
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};

pub fn verify_on_g2<'a>(public_key: &[u8], message: &[u8], signature: &[u8], domain_separation_tag: &str) -> Result<(), &'a str> {
    let pub_key_bytes: &[u8; 48] = public_key
        .try_into()
        .map_err(|_| "public key wrong length")?;

    let sig_bytes: &[u8; 96] = signature
        .try_into()
        .map_err(|_| "signature wrong length")?;

    let p = G1Affine::from_compressed(pub_key_bytes).unwrap();
    let q = G2Affine::from_compressed(sig_bytes).unwrap();

    if p.is_on_curve().unwrap_u8() != 1 {
        return Err("not on curve");
    }

    if p.is_identity().unwrap_u8() == 1 {
        return Err("cannot use point at infinity");
    }

    if message.len() == 0 {
        return Err("message can't be empty");
    }

    if signature.len() == 0 {
        return Err("signature can't be empty");
    }

    let m = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
        &message, domain_separation_tag.as_bytes(),
    );

    let m_prepared = G2Prepared::from(G2Affine::from(m));
    let q_prepared = G2Prepared::from(q);
    let exp = multi_miller_loop(
        &[
            (&p.neg(), &m_prepared),
            (&G1Affine::generator(), &q_prepared)
        ]
    );

    if exp.final_exponentiation() != Gt::identity() {
        Err("verification failed")
    } else {
        Ok(())
    }
}

pub fn verify_on_g1<'a>(public_key: &[u8], message: &[u8], signature: &[u8], domain_separation_tag: &str) -> Result<(), &'a str> {
    let pub_key_bytes: &[u8; 96] = public_key
        .try_into()
        .map_err(|_| "public key wrong length")?;

    let sig_bytes: &[u8; 48] = signature
        .try_into()
        .map_err(|_| "signature wrong length")?;

    let signature_point = G1Affine::from_compressed(sig_bytes).unwrap();
    let pubkey_point = G2Affine::from_compressed(pub_key_bytes).unwrap();

    if pubkey_point.is_on_curve().unwrap_u8() != 1 {
        return Err("not on curve");
    }

    if pubkey_point.is_identity().unwrap_u8() == 1 {
        return Err("cannot use point at infinity");
    }

    if message.len() == 0 {
        return Err("message can't be empty");
    }

    if signature.len() == 0 {
        return Err("signature can't be empty");
    }

    let m = <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
        &message, domain_separation_tag.as_bytes(),
    );

    let pubkey_prepared = G2Prepared::from(pubkey_point.neg());
    let g2_base = G2Prepared::from(G2Affine::generator());
    let exp = multi_miller_loop(
        &[
            (&G1Affine::from(m), &pubkey_prepared),
            (&signature_point, &g2_base)
        ]
    );

    if exp.final_exponentiation() != Gt::identity() {
        Err("verification failed")
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use sha2::Digest;
    use crate::verify::{verify_on_g2, verify_on_g1};

    #[test]
    fn g1_verifies_a_beacon() -> Result<(), ()> {
        let public_key = hex::decode("88a8227b75dba145599d894d33eebde3b36fef900d456ae2cc4388867adb4769c40359f783750a41b4d17e40f578bfdb").unwrap();
        let round: u64 = 397089;
        let sig = hex::decode("88ccd9a91946bc0bbef2c6c60a09bbf4a247b1d2059522449aa1a35758feddfad85efe818bbde3e1e4ab0c852d96e65f0b1f97f239bf3fc918860ea846cbb500fcf7c9d0dd3d851320374460b5fc596b8cfd629f4c07c7507c259bf9beca850a").unwrap();
        let prev_sig = hex::decode("a2237ee39a1a6569cb8e02c6e979c07efe1f30be0ac501436bd325015f1cd6129dc56fd60efcdf9158d74ebfa34bfcbd17803dbca6d2ae8bc3a968e4dc582f8710c69de80b2e649663fef5742d22fff7d1619b75d5f222e8c9b8840bc2044bce").unwrap();

        let mut message = Vec::new();
        message.extend(prev_sig);
        message.extend(round.to_be_bytes());

        let m = sha2::Sha256::digest(message.as_slice());

        let _ = verify_on_g2(&public_key, &m.to_vec(), &sig, "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_").unwrap();
        Ok(())
    }

    #[test]
    fn g1_unchained_beacon_verifies() -> Result<(), ()> {
        let public_key = hex::decode("8d91ae0f4e3cd277cfc46aba26680232b0d5bb4444602cdb23442d62e17f43cdffb1104909e535430c10a6a1ce680a65").unwrap();
        let round: u64 = 397092;
        let sig = hex::decode("94da96b5b985a22a3d99fa3051a42feb4da9218763f6c836fca3770292dbf4b01f5d378859a113960548d167eaa144250a2c8e34c51c5270152ac2bc7a52632236f746545e0fae52f69068c017745204240d19dae2b4d038cef3c6047fcd6539").unwrap();

        let mut message = Vec::new();
        message.extend(round.to_be_bytes());

        let m = sha2::Sha256::digest(message.as_slice());

        let _ = verify_on_g2(&public_key, &m.to_vec(), &sig, "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_").unwrap();
        Ok(())
    }

    #[test]
    fn g2_non_rfc_verifies_a_beacon() -> Result<(), ()> {
        let public_key = hex::decode("a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e").unwrap();
        let round: u64 = 3;
        let sig = hex::decode("8176555f90d71aa49ceb37739683749491c2bab15a46094b255289ed25cf8f01cdfb1fe8bd9cd5a19eb09448a3e53186").unwrap();

        let m = sha2::Sha256::digest(round.to_be_bytes().as_slice());

        let _ = verify_on_g1(&public_key, &m.to_vec(), &sig, "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_").unwrap();
        Ok(())
    }

    #[test]
    fn g2_rfc_verifies_a_beacon() -> Result<(), ()> {
        let public_key = hex::decode("83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a").unwrap();
        let round: u64 = 1000;
        let sig = hex::decode("b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39").unwrap();

        let m = sha2::Sha256::digest(round.to_be_bytes().as_slice());

        let _ = verify_on_g1(&public_key, &m.to_vec(), &sig, "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_").unwrap();
        Ok(())
    }
}
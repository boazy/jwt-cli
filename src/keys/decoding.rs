use jsonwebtoken::{jwk, Algorithm, DecodingKey, Header};
use crate::utils::{JWTError, JWTResult};

pub fn decoding_key_from_jwks_secret(
    jwks: bool,
    secret: &[u8],
    header: Option<Header>,
    alg: Algorithm,
) -> JWTResult<DecodingKey> {
    let Some(h) = header else {
        return Err(JWTError::Internal("Invalid jwt header".to_string()));
    };

    if h.alg != alg {
        return Err(JWTError::Internal(format!(
            "Invalid algorithm in header: expected {:?}, got {:?}",
            alg, h.alg
        )));
    }

    if jwks {
        match serde_json::from_slice::<jwk::JwkSet>(secret) {
            Ok(jwks) => decoding_key_from_jwks(jwks, &h),
            Err(e) => Err(JWTError::Internal(format!("Invalid jwks format: %{e}"))),
        }
    } else {
        match serde_json::from_slice::<jwk::Jwk>(secret) {
            Ok(jwk) => decoding_key_from_jwks(jwk::JwkSet { keys: vec![jwk] }, &h),
            Err(e) => Err(JWTError::Internal(format!("Invalid jwk format: %{e}"))),
        }
    }
}

fn decoding_key_from_jwks(jwks: jwk::JwkSet, header: &Header) -> JWTResult<DecodingKey> {
    let kid = match &header.kid {
        Some(k) => k.to_owned(),
        None => {
            return Err(JWTError::Internal(
                "Missing 'kid' from jwt header".to_string(),
            ));
        }
    };

    let jwk = match jwks.find(&kid) {
        Some(j) => j,
        None => {
            return Err(JWTError::Internal(format!(
                "No jwk found for 'kid' {kid:?}",
            )));
        }
    };

    DecodingKey::from_jwk(jwk).map_err(jsonwebtoken::errors::Error::into)
}
use crate::keys::pkcs1_der::pkcs1_der_from_jwk;
use crate::utils::{JWTError, JWTResult};
use jsonwebkey::JsonWebKey;
use jsonwebtoken::{Algorithm, EncodingKey};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct JsonWebKeySet {
    keys: Vec<JsonWebKey>,
}

pub fn encoding_key_from_jwks_secret(jwks: bool, alg: Algorithm, secret: &[u8]) -> JWTResult<EncodingKey> {
    let jwk = if jwks {
        let Ok(key_set) = serde_json::from_slice::<JsonWebKeySet>(secret) else {
            return Err(JWTError::Internal("Invalid jwks format".to_string()));
        };

        let Some(first_key) = key_set.keys.into_iter().next() else {
            return Err(JWTError::Internal("Empty jwks".to_string()));
        };

        first_key
    } else {
        let Ok(key) = serde_json::from_slice::<JsonWebKey>(secret) else {
            return Err(JWTError::Internal("Invalid jwk format".to_string()));
        };

        key
    };

    encoding_key_from_jwk(alg, &jwk)
}

fn encoding_key_from_jwk(
    alg: Algorithm,
    jwk: &JsonWebKey,
) -> JWTResult<EncodingKey> {
    match alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            let der = pkcs1_der_from_jwk(jwk)?;
            Ok(EncodingKey::from_rsa_der(&der))
        }
        _ => Err(JWTError::Internal("Unsupported algorithm".to_string())),
    }
}
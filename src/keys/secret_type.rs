use serde::Deserialize;
use serde_json::value::RawValue;
use strum::Display;
use jsonwebtoken::Algorithm;
use crate::utils;
use crate::utils::{JWTError, JWTResult};

#[derive(Display)]
pub enum SecretType {
    #[strum(serialize = "PEM")]
    Pem,

    #[strum(serialize = "DER")]
    Der,

    #[strum(serialize = "JWK")]
    Jwk,

    #[strum(serialize = "JWKS")]
    Jwks,

    #[strum(serialize = "Base64")]
    B64,

    Plain,
}

pub fn get_secret_from_file_or_input(
    alg: Algorithm,
    secret_string: &str,
) -> JWTResult<(Vec<u8>, SecretType)> {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            if secret_string.starts_with('@') {
                let content = utils::slurp_file(strip_leading_symbol(secret_string));
                let secret_type =
                    detect_secret_type_from_content(&[SecretType::Jwk, SecretType::Jwks], &content)
                        .unwrap_or(SecretType::Plain);

                Ok((content, secret_type))
            } else if secret_string.starts_with("b64:") {
                Ok((
                    secret_string
                        .chars()
                        .skip(4)
                        .collect::<String>()
                        .as_bytes()
                        .to_owned(),
                    SecretType::B64,
                ))
            } else {
                Ok((secret_string.as_bytes().to_owned(), SecretType::Plain))
            }
        }
        _ => {
            if secret_string.starts_with('@') {
                let content = utils::slurp_file(strip_leading_symbol(secret_string));
                let secret_type = detect_secret_type_from_content(
                    &[
                        SecretType::Pem,
                        SecretType::Jwk,
                        SecretType::Jwks,
                        SecretType::Der,
                    ],
                    &content,
                );

                if let Some(secret_type) = secret_type {
                    Ok((content, secret_type))
                } else {
                    let err_message = match detect_any_secret_type_from_content(&content) {
                        Some(t) => format!("Invalid secret file type for {alg:?} - {t}"),
                        None => format!(
                            "Invalid secret file type for {alg:?} - unable to detect secret type"
                        ),
                    };
                    Err(JWTError::Internal(err_message))
                }
            } else {
                // allows to read JWKS from argument (e.g. output of 'curl https://auth.domain.com/jwks.json')
                Ok((secret_string.as_bytes().to_vec(), SecretType::Jwks))
            }
        }
    }
}

fn detect_any_secret_type_from_content(content: &[u8]) -> Option<SecretType> {
    detect_secret_type_from_content(
        &[
            SecretType::Pem,
            SecretType::Jwk,
            SecretType::Jwks,
            SecretType::Der,
        ],
        content,
    )
}

fn detect_secret_type_from_content(
    expected_types: &[SecretType],
    content: &[u8],
) -> Option<SecretType> {
    for secret_type in expected_types {
        match secret_type {
            SecretType::Pem => {
                let trimmed_content = content.trim_ascii_start();
                if trimmed_content.starts_with(b"-----BEGIN") {
                    return Some(SecretType::Pem);
                }
            }
            SecretType::Jwk => {
                if attempt_json_format::<JwkDetection>(content) {
                    return Some(SecretType::Jwks);
                }
            }
            SecretType::Jwks => {
                if attempt_json_format::<JwksDetection>(content) {
                    return Some(SecretType::Jwks);
                }
            }
            SecretType::Der => {
                if content.starts_with(b"\x30") {
                    // 0x30 signifies the start of a DER-encoded sequence. All
                    // DER keys are defined as sequences.
                    return Some(SecretType::Der);
                }
            }
            _ => {
                // Other secret types cannot be auto-detected
            }
        }
    }
    None
}

fn strip_leading_symbol(secret_string: &str) -> String {
    secret_string.chars().skip(1).collect::<String>()
}

fn attempt_json_format<'a, T: Deserialize<'a>>(content: &'a [u8]) -> bool {
    match serde_json::from_slice::<T>(&content) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[derive(Deserialize)]
struct JwksDetection<'a> {
    #[allow(dead_code)]
    #[serde(borrow)]
    keys: &'a RawValue,
}

#[derive(Deserialize)]
struct JwkDetection<'a> {
    #[allow(dead_code)]
    #[serde(borrow)]
    kty: &'a RawValue,
}
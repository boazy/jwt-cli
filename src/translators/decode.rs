use crate::cli_config::{translate_algorithm, DecodeArgs};
use crate::keys::{decoding_key_from_jwks_secret, get_secret_from_file_or_input, SecretType};
use crate::translators::Payload;
use crate::utils::{write_file, JWTError, JWTResult};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Header, TokenData, Validation};
use serde_derive::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use std::collections::HashSet;
use std::io;
use std::path::PathBuf;
use std::str::from_utf8;

#[derive(Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct TokenOutput {
    pub header: Header,
    pub payload: Payload,
}

impl TokenOutput {
    fn new(data: TokenData<Payload>) -> Self {
        TokenOutput {
            header: data.header,
            payload: data.claims,
        }
    }
}

pub fn decoding_key_from_secret(
    alg: Algorithm,
    secret_string: &str,
    header: Option<Header>,
) -> JWTResult<DecodingKey> {
    let (secret, file_type) = get_secret_from_file_or_input(alg, secret_string)?;
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => match file_type {
            SecretType::Plain => Ok(DecodingKey::from_secret(&secret)),
            SecretType::Jwk => decoding_key_from_jwks_secret(false, &secret, header, alg),
            SecretType::Jwks => decoding_key_from_jwks_secret(true, &secret, header, alg),
            SecretType::B64 => DecodingKey::from_base64_secret(from_utf8(&secret)?)
                .map_err(jsonwebtoken::errors::Error::into),
            _ => Err(JWTError::Internal(format!(
                "Invalid secret file type for {alg:?}"
            ))),
        },
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => decode_public_key(
            alg,
            DecodingKey::from_rsa_pem,
            DecodingKey::from_rsa_der,
            file_type,
            &secret,
            header,
        ),
        Algorithm::ES256 | Algorithm::ES384 => decode_public_key(
            alg,
            DecodingKey::from_ec_pem,
            DecodingKey::from_ec_der,
            file_type,
            &secret,
            header,
        ),
        Algorithm::EdDSA => decode_public_key(
            alg,
            DecodingKey::from_ed_pem,
            DecodingKey::from_ed_der,
            file_type,
            &secret,
            header,
        ),
    }
}

pub fn decode_token(
    arguments: &DecodeArgs,
) -> (
    JWTResult<TokenData<Payload>>,
    JWTResult<TokenData<Payload>>,
    OutputFormat,
) {
    let jwt = match arguments.jwt.as_str() {
        "-" => {
            let mut buffer = String::new();

            io::stdin()
                .read_line(&mut buffer)
                .expect("STDIN was not valid UTF-8");

            buffer
        }
        _ => arguments.jwt.clone(),
    }
    .trim()
    .to_owned();

    let header = decode_header(&jwt).ok();

    let algorithm = if arguments.algorithm.is_some() {
        translate_algorithm(arguments.algorithm.as_ref().unwrap())
    } else {
        header.as_ref().map(|h| h.alg).unwrap_or(Algorithm::HS256)
    };

    let secret = match arguments.secret.len() {
        0 => None,
        _ => Some(decoding_key_from_secret(
            algorithm,
            &arguments.secret,
            header,
        )),
    };

    let mut secret_validator = Validation::new(algorithm);

    secret_validator.leeway = 1000;
    secret_validator.validate_aud = false;

    if arguments.ignore_exp {
        secret_validator
            .required_spec_claims
            .retain(|claim| claim != "exp");
        secret_validator.validate_exp = false;
    }

    let mut insecure_validator = secret_validator.clone();
    let insecure_decoding_key = DecodingKey::from_secret("".as_ref());

    insecure_validator.insecure_disable_signature_validation();
    insecure_validator.required_spec_claims = HashSet::new();
    insecure_validator.validate_exp = false;

    let token_data = decode::<Payload>(&jwt, &insecure_decoding_key, &insecure_validator)
        .map_err(jsonwebtoken::errors::Error::into)
        .map(|mut token| {
            if arguments.time_format.is_some() {
                token
                    .claims
                    .convert_timestamps(arguments.time_format.unwrap_or(super::TimeFormat::UTC));
            }

            token
        });

    (
        match secret {
            Some(Ok(secret_key)) => decode::<Payload>(&jwt, &secret_key, &secret_validator)
                .map_err(jsonwebtoken::errors::Error::into),
            Some(Err(err)) => Err(err),
            None => decode::<Payload>(&jwt, &insecure_decoding_key, &insecure_validator)
                .map_err(jsonwebtoken::errors::Error::into),
        },
        token_data,
        if arguments.json {
            OutputFormat::Json
        } else {
            OutputFormat::Text
        },
    )
}

pub fn print_decoded_token(
    validated_token: JWTResult<TokenData<Payload>>,
    token_data: JWTResult<TokenData<Payload>>,
    format: OutputFormat,
    output_path: &Option<PathBuf>,
) -> JWTResult<()> {
    if let Err(err) = &validated_token {
        match err {
            JWTError::External(ext_err) => {
                match ext_err.kind() {
                    ErrorKind::InvalidToken => bunt::println!("{$red+bold}The JWT provided is invalid{/$}"),
                    ErrorKind::InvalidSignature => bunt::eprintln!("{$red+bold}The JWT provided has an invalid signature{/$}"),
                    ErrorKind::InvalidEcdsaKey => bunt::eprintln!("{$red+bold}The secret provided isn't a valid ECDSA key{/$}"),
                    ErrorKind::InvalidRsaKey(_) => bunt::eprintln!("{$red+bold}The secret provided isn't a valid RSA key{/$}"),
                    ErrorKind::MissingRequiredClaim(missing) => {
                        if missing.as_str() == "exp" {
                            bunt::eprintln!("{$red+bold}`exp` is missing, but is required. This error can be ignored via the `--ignore-exp` parameter.{/$}")
                        } else {
                            bunt::eprintln!("{$red+bold}`{:?}` is missing, but is required{/$}", missing)
                        }
                    }
                    ErrorKind::ExpiredSignature => bunt::eprintln!("{$red+bold}The token has expired (or the `exp` claim is not set). This error can be ignored via the `--ignore-exp` parameter.{/$}"),
                    ErrorKind::InvalidIssuer => bunt::println!("{$red+bold}The token issuer is invalid{/$}"),
                    ErrorKind::InvalidAudience => bunt::eprintln!("{$red+bold}The token audience doesn't match the subject{/$}"),
                    ErrorKind::InvalidSubject => bunt::eprintln!("{$red+bold}The token subject doesn't match the audience{/$}"),
                    ErrorKind::ImmatureSignature => bunt::eprintln!(
                        "{$red+bold}The `nbf` claim is in the future which isn't allowed{/$}"
                    ),
                    ErrorKind::InvalidAlgorithm => bunt::eprintln!(
                        "{$red+bold}The JWT provided has a different signing algorithm than the one you \
                                             provided{/$}",
                    ),
                    ErrorKind::InvalidAlgorithmName => bunt::eprintln!(
                        "{$red+bold}The JWT provided has a different signing algorithm than the one you \
                                             provided{/$}",
                    ),
                    ErrorKind::InvalidKeyFormat => bunt::eprintln!("{$red+bold}The key provided is an invalid format{/$}"),
                    _ => bunt::eprintln!(
                        "{$red+bold}The JWT provided is invalid because{/$} {}",
                        err
                    ),
                };
            }
            JWTError::Internal(int_err) => bunt::eprintln!("{$red+bold}{:?}{/$}", int_err),
        };
        return Err(validated_token.err().unwrap());
    }

    match (output_path.as_ref(), format, token_data) {
        (Some(path), _, Ok(token)) => {
            let json = to_string_pretty(&TokenOutput::new(token)).unwrap();
            write_file(path, json.as_bytes());
            println!("Wrote jwt to file {}", path.display());
        }
        (None, OutputFormat::Json, Ok(token)) => {
            println!("{}", to_string_pretty(&TokenOutput::new(token)).unwrap());
        }
        (None, _, Ok(token)) => {
            bunt::println!("\n{$bold}Token header\n------------{/$}");
            println!("{}\n", to_string_pretty(&token.header).unwrap());
            bunt::println!("{$bold}Token claims\n------------{/$}");
            println!("{}", to_string_pretty(&token.claims).unwrap());
        }
        (_, _, Err(err)) => return Err(err),
    }

    Ok(())
}

fn decode_public_key(
    alg: Algorithm,
    pem_decoder: impl Fn(&[u8]) -> jsonwebtoken::errors::Result<DecodingKey>,
    der_decoder: impl Fn(&[u8]) -> DecodingKey,
    secret_type: SecretType,
    secret: &[u8],
    header: Option<Header>,
) -> JWTResult<DecodingKey> {
    match secret_type {
        SecretType::Pem => pem_decoder(secret).map_err(jsonwebtoken::errors::Error::into),
        SecretType::Der => Ok(der_decoder(secret)),
        SecretType::Jwk => decoding_key_from_jwks_secret(false, &secret, header, alg),
        SecretType::Jwks => decoding_key_from_jwks_secret(true, &secret, header, alg),
        _ => Err(JWTError::Internal(format!(
            "Invalid secret file type ({secret_type}) for {alg:?}"
        ))),
    }
}

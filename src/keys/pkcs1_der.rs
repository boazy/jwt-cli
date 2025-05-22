use crate::utils::{JWTError, JWTResult};
use jsonwebkey::{JsonWebKey, Key};

pub fn pkcs1_der_from_jwk(jwk: &JsonWebKey) -> JWTResult<Vec<u8>> {
    let Key::RSA { public, private } = jwk.key.as_ref() else {
        return Err(JWTError::Internal("Invalid JWK key type".to_string()));
    };

    let Some(private) = private else {
        return Err(JWTError::Internal(
            "Private key not found in JWK".to_string(),
        ));
    };

    let mut der = AsnSequence::new();
    der.add_int(&[0]); // Version
    der.add_unsigned_int(&public.n);
    der.add_unsigned_int(&[1, 0, 1]); // Public exponent (65537a
    der.add_unsigned_int(&private.d);

    match (
        &private.p,
        &private.q,
        &private.dp,
        &private.dq,
        &private.qi,
    ) {
        (Some(p), Some(q), Some(dp), Some(dq), Some(qi)) => {
            der.add_unsigned_int(&p);
            der.add_unsigned_int(&q);
            der.add_unsigned_int(&dp);
            der.add_unsigned_int(&dq);
            der.add_unsigned_int(&qi);
        }
        _ => {
            return Err(JWTError::Internal(
                "Missing required private key parameters".to_string(),
            ));
        }
    };

    Ok(der.to_vec())
}

struct AsnSequence<'a> {
    items: Vec<AsnItem<'a>>,
}

impl<'a> AsnSequence<'a> {
    pub fn new() -> Self {
        AsnSequence { items: Vec::new() }
    }

    pub fn add_int(&mut self, value: &'a [u8]) {
        self.items.push(AsnItem::Integer(value));
    }

    pub fn add_unsigned_int(&mut self, value: &'a [u8]) {
        self.items.push(AsnItem::UnsignedInteger(value));
    }

    fn content_length(&self) -> usize {
        self.items
            .iter()
            .map(|item| item.encoded_tagged_len())
            .sum::<usize>()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let content_length = self.content_length();
        let encoded_length = 1 + encoded_asn1_length_size(content_length) + content_length;
        let mut dest = Vec::with_capacity(encoded_length);
        dest.push(0x30); // Sequence tag
        encode_asn1_len(&mut dest, content_length);
        for item in &self.items {
            item.encode(&mut dest);
        }
        dest
    }
}

enum AsnItem<'a> {
    Integer(&'a [u8]),
    UnsignedInteger(&'a [u8]),
}

impl<'a> AsnItem<'a> {
    fn encoded_content_len(&self) -> usize {
        match self {
            AsnItem::Integer(value) => value.len(),
            AsnItem::UnsignedInteger(value) => {
                ZeroPaddedBigInt(value).len_with_padding()
            }
        }
    }

    fn encoded_tagged_len(&self) -> usize {
        let len = self.encoded_content_len();
        self.tag_len() + encoded_asn1_length_size(len) + len
    }

    fn tag_len(&self) -> usize {
        1
    }

    fn encode(&self, dest: &mut Vec<u8>) {
        match self {
            AsnItem::Integer(value) => {
                dest.push(0x02);
                encode_asn1_len(dest, self.encoded_content_len());
                dest.extend_from_slice(value);
            }
            AsnItem::UnsignedInteger(value) => {
                dest.push(0x02);
                encode_asn1_len(dest, self.encoded_content_len());
                if ZeroPaddedBigInt(value).requires_padding() {
                    // If the first byte is high, we need to add a leading zero byte
                    // to make it positive.
                    dest.push(0);
                }
                dest.extend_from_slice(value);
            }
        }
    }
}

fn encoded_asn1_length_size(len: usize) -> usize {
    if len < 0x7F {
        1
    } else {
        1 + calc_full_length_size(len) as usize
    }
}

fn encode_asn1_len(dest: &mut Vec<u8>, len: usize) {
    if len < 0x7F {
        dest.push(len as u8);
        return;
    }

    let size = calc_full_length_size(len);

    dest.push(0x80 | size);
    for i in (0..size).rev() {
        dest.push(((len >> (i * 8)) & 0xFF) as u8);
    }
}

fn calc_full_length_size(len: usize) -> u8 {
    let mut size = 0u8;
    let mut len_count = len;
    loop {
        size += 1;
        len_count >>= 8;
        if len_count == 0 {
            break;
        }
    }
    size
}

struct ZeroPaddedBigInt<'a>(&'a [u8]);

impl <'a> ZeroPaddedBigInt<'a> {
    fn requires_padding(&self) -> bool {
        self.0.first().is_some_and(|x| x & 0x80 != 0)
    }

    fn len_with_padding(&self) -> usize {
        if self.requires_padding() {
            // If the first byte is high, we need to add a leading zero byte
            // to make it positive.
            self.0.len() + 1
        } else {
            self.0.len()
        }
    }
}
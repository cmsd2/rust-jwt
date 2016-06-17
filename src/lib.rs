//! Create and parses JWT (JSON Web Tokens)
//!
#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

#![recursion_limit="100"] // for quick-error
#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

extern crate rustc_serialize;
extern crate crypto as rust_crypto;
#[macro_use] extern crate quick_error;
extern crate serde;
extern crate serde_json;
extern crate openssl;
#[macro_use] extern crate log;
extern crate chrono;
extern crate time;
extern crate cast;

use rustc_serialize::base64::{self, ToBase64, FromBase64};
use serde::{Serialize, Deserialize};

pub mod jwk;
pub mod signer;
pub mod verifier;
pub mod algorithm;
pub mod result;
pub mod header;
pub mod crypto;
pub mod key_type;
pub mod bignum;
pub mod claims;
pub mod jwt;
pub mod json;
pub mod validation;

use header::*;
use result::*;
use signer::Signer;
use verifier::Verifier;

/// A part of the JWT: header and claims specifically
/// Allows converting from/to struct with base64
pub trait Part {
    type Encoded: AsRef<str>;

    fn from_base64<B: AsRef<[u8]>>(encoded: B) -> JwtResult<Self> where Self: Sized;
    fn to_base64(&self) -> JwtResult<Self::Encoded>;
}

impl<T> Part for T where T: Serialize + Deserialize {
    type Encoded = String;

    fn to_base64(&self) -> JwtResult<Self::Encoded> {
        let encoded = try!(serde_json::ser::to_string(&self));
        Ok(encoded.as_bytes().to_base64(base64::URL_SAFE))
    }

    fn from_base64<B: AsRef<[u8]>>(encoded: B) -> JwtResult<T> {
        let decoded = try!(encoded.as_ref().from_base64());
        let s = try!(String::from_utf8(decoded));
        Ok(try!(serde_json::from_str(&s)))
    }
}

#[derive(Debug)]
/// The return type of a successful call to decode(...)
pub struct TokenData<T: Part> {
    pub header: Header,
    pub claims: T
}

/// Encode the claims passed and sign the payload using the algorithm from the header and the secret
pub fn encode<T: Part, S: Signer>(header: Header, claims: &T, signer: &S) -> JwtResult<String> {
    let encoded_header = try!(header.to_base64());
    let encoded_claims = try!(claims.to_base64());
    // seems to be a tiny bit faster than format!("{}.{}", x, y)
    let payload = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = try!(signer.sign(&header, &payload.as_bytes()));

    Ok([payload, signature].join("."))
}

/// Used in decode: takes the result of a rsplit and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter; // evaluate the expr
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => (first, second),
            _ => return Err(JwtError::InvalidToken)
        }
    }}
}

/// Decode a token into a Claims struct
/// If the token or its signature is invalid, it will return an error
pub fn decode<T: Part, V: Verifier>(token: &str, verifier: &V) -> JwtResult<TokenData<T>> {
    let (signature, payload) = expect_two!(token.rsplitn(2, '.'));

    let (claims, header) = expect_two!(payload.rsplitn(2, '.'));

    let header = try!(Header::from_base64(header));
    
    let is_valid = try!(verifier.verify(
        &header,
        &payload.as_bytes(),
        signature
    ));

    if !is_valid {
        return Err(JwtError::InvalidSignature);
    }

    let decoded_claims = try!(T::from_base64(claims));

    Ok(TokenData { header: header, claims: decoded_claims})
}

#[cfg(test)]
mod tests {
    use super::{encode, decode};
    use algorithm::*;
    use header::*;
    use crypto::mac_signer::MacSigner;
    use signer::Signer;
    use verifier::Verifier;

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        company: String
    }

    #[test]
    fn sign_hs256() {
        let signer = MacSigner::new("secret".as_bytes()).unwrap();
        let header = Header::new(Algorithm::HS256);
        let result = signer.sign(&header, "hello world".as_bytes()).unwrap();
        let expected = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
        assert_eq!(result, expected);
    }

    #[test]
    fn verify_hs256() {
        let signer = MacSigner::new("secret".as_bytes()).unwrap();
        let header = Header::new(Algorithm::HS256);
        let sig = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
        let valid = signer.verify(&header, "hello world".as_bytes(), sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn encode_with_custom_header() {
        // TODO: test decode value
        let my_claims = Claims {
            sub: "b@b.com".to_owned(),
            company: "ACME".to_owned()
        };
        let signer = MacSigner::new("secret".as_bytes()).unwrap();
        let mut header = Header::default();
        header.kid = Some("kid".to_owned());
        let token = encode(header, &my_claims, &signer).unwrap();
        let token_data = decode::<Claims, MacSigner>(&token, &signer).unwrap();
        assert_eq!(my_claims, token_data.claims);
        assert_eq!("kid", token_data.header.kid.unwrap());
    }

    #[test]
    fn round_trip_claim() {
        let my_claims = Claims {
            sub: "b@b.com".to_owned(),
            company: "ACME".to_owned()
        };
        let signer = MacSigner::new("secret".as_bytes()).unwrap();
        let token = encode(Header::default(), &my_claims, &signer).unwrap();
        let token_data = decode::<Claims, MacSigner>(&token, &signer).unwrap();
        assert_eq!(my_claims, token_data.claims);
        assert!(token_data.header.kid.is_none());
    }

    #[test]
    fn decode_token() {
        let signer = MacSigner::new("secret".as_bytes()).unwrap();
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.I1BvFoHe94AFf09O6tDbcSB8-jp8w6xZqmyHIwPeSdY";
        let claims = decode::<Claims, MacSigner>(token, &signer);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidToken")]
    fn decode_token_missing_parts() {
        let signer = MacSigner::new("secret".as_bytes()).unwrap();
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = decode::<Claims, MacSigner>(token, &signer);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn decode_token_invalid_signature() {
        let signer = MacSigner::new("secret".as_bytes()).unwrap();
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.wrong";
        let claims = decode::<Claims, MacSigner>(token, &signer);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn decode_token_wrong_algorithm() {
        let signer = MacSigner::new("secret".as_bytes()).unwrap();
        let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI";
        let claims = decode::<Claims, MacSigner>(token, &signer);
        claims.unwrap();
    }

    #[test]
    fn decode_token_with_bytes_secret() {
        let signer = MacSigner::new(b"\x01\x02\x03".as_ref()).unwrap();
        let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiY29tcGFueSI6Ikdvb2dvbCJ9.27QxgG96vpX4akKNpD1YdRGHE3_u2X35wR3EHA2eCrs";
        let claims = decode::<Claims, MacSigner>(token, &signer);
        assert!(claims.is_ok());
    }

    #[test]
    fn decode_token_with_shuffled_header_fields() {
        let signer = MacSigner::new("secret".as_bytes()).unwrap();
        let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjb21wYW55IjoiMTIzNDU2Nzg5MCIsInN1YiI6IkpvaG4gRG9lIn0.SEIZ4Jg46VGhquuwPYDLY5qHF8AkQczF14aXM3a2c28";
        let claims = decode::<Claims, MacSigner>(token, &signer);
        assert!(claims.is_ok());
    }
}

use jwk::*;
use result::*;
use ring::{digest, signature};
use openssl::hash;
use openssl::bn::BigNumRef;
use openssl;
use openssl::types::OpenSslTypeRef;
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl_sys::{BIGNUM};
use rust_crypto::digest::Digest;
use rust_crypto::sha2::{Sha256, Sha384, Sha512};
use rustc_serialize::base64::*;
use algorithm::*;
use signer::*;
use header::*;
use validation::*;
use json::*;
use key_type::*;
use bignum::*;

pub fn bn_to_b64(bn: &BigNumRef) -> JwtResult<String> {
    use Part;

    let component = BigNumComponent(try!(bn.to_owned()));
    component.to_base64().map_err(From::from)
}

pub trait RsaParameters {
    fn dp(&self) -> Option<&BigNumRef>;
    fn dq(&self) -> Option<&BigNumRef>;
    fn qi(&self) -> Option<&BigNumRef>;
}

impl RsaParameters for Rsa {
    fn dp(&self) -> Option<&BigNumRef> {
        unsafe {
            let dp: *mut BIGNUM = (*self.as_ptr()).dmp1;
            if dp.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(dp as *mut _))
            }
        }
    }

    fn dq(&self) -> Option<&BigNumRef> {
        unsafe {
            let dq: *mut BIGNUM = (*self.as_ptr()).dmq1;
            if dq.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(dq as *mut _))
            }
        }
    }

    fn qi(&self) -> Option<&BigNumRef> {
        unsafe {
            let qi: *mut BIGNUM = (*self.as_ptr()).iqmp;
            if qi.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(qi as *mut _))
            }
        }
    }
}

pub trait RsaKey {
    fn convert_private_pem_to_jwk(self) -> JwtResult<Jwk>;

    fn convert_public_pem_to_jwk(self) -> JwtResult<Jwk>;
}

impl RsaKey for Rsa {
    fn convert_private_pem_to_jwk(self) -> JwtResult<Jwk> {
        let mut vs = ValidationState::new();
    
        if self.n().is_none() {
            vs.reject("n", ValidationError::MissingRequiredValue("n".to_owned()));
        }
    
        if self.e().is_none() {
            vs.reject("e", ValidationError::MissingRequiredValue("e".to_owned()));
        }

        if self.d().is_none() {
            vs.reject("d", ValidationError::MissingRequiredValue("d".to_owned()));
        }

        if self.p().is_none() {
            vs.reject("p", ValidationError::MissingRequiredValue("p".to_owned()));
        }
    
        if self.q().is_none() {
            vs.reject("q", ValidationError::MissingRequiredValue("q".to_owned()));
        }

        if self.dp().is_none() {
            vs.reject("dp", ValidationError::MissingRequiredValue("dp".to_owned()));
        }

        if self.dq().is_none() {
            vs.reject("dq", ValidationError::MissingRequiredValue("dq".to_owned()));
        }

        if self.qi().is_none() {
            vs.reject("qi", ValidationError::MissingRequiredValue("qi".to_owned()));
        }

        if vs.valid {
            let mut jwk = Jwk::new(KeyType::RSA);
        
            let n = self.n().unwrap();
            jwk.set_value("n", &try!(bn_to_b64(n)));
        
            let e = self.e().unwrap();
            jwk.set_value("e", &try!(bn_to_b64(e)));
        
            let d = self.d().unwrap();
            jwk.set_value("d", &try!(bn_to_b64(d)));
        
            let p = self.p().unwrap();
            jwk.set_value("p", &try!(bn_to_b64(p)));
        
            let q = self.q().unwrap();
            jwk.set_value("q", &try!(bn_to_b64(q)));
        
            let dp = self.dp().unwrap();
            jwk.set_value("dp", &try!(bn_to_b64(dp)));
        
            let dq = self.dq().unwrap();
            jwk.set_value("dq", &try!(bn_to_b64(dq)));
        
            let qi = self.qi().unwrap();
            jwk.set_value("qi", &try!(bn_to_b64(qi)));
        
            Ok(jwk)
        } else {
            Err(From::from(ValidationError::ValidationError(vs)))
        }
    }

    fn convert_public_pem_to_jwk(self) -> JwtResult<Jwk> {
        use Part;

        let mut vs = ValidationState::new();

        if self.n().is_none() {
            vs.reject("n", ValidationError::MissingRequiredValue("n".to_owned()));
        }
    
        if self.e().is_none() {
            vs.reject("e", ValidationError::MissingRequiredValue("e".to_owned()));
        }
    
        if vs.valid {
            let mut jwk = Jwk::new(KeyType::RSA);
        
            let n = self.n().unwrap();
            let n_bn = BigNumComponent(try!(n.to_owned()));
            let n_b64 = try!(n_bn.to_base64());
            jwk.set_value("n", &n_b64);
        
            let e = self.e().unwrap();
            let e_bn = BigNumComponent(try!(e.to_owned()));
            let e_b64 = try!(e_bn.to_base64());
            jwk.set_value("e", &e_b64);
        
            Ok(jwk)
        } else {
            Err(From::from(ValidationError::ValidationError(vs)))
        }
    }
}

pub trait RsaJwk {
    fn public_key(&self) -> JwtResult<Rsa>;
    
    fn private_key(&self) -> JwtResult<Rsa>;
    
    fn is_private_key(&self) -> bool;
}

impl RsaJwk for Jwk {
    fn public_key(&self) -> JwtResult<Rsa> {
        let n = try!(self.get_bignum_param("n"));
        let e = try!(self.get_bignum_param("e"));        
        
        Rsa::from_public_components(n, e).map_err(JwtError::from)
    }
    
    fn private_key(&self) -> JwtResult<Rsa> {
        let n = try!(self.get_bignum_param("n"));
        let e = try!(self.get_bignum_param("e"));       
        let d = try!(self.get_bignum_param("d"));
        let p = try!(self.get_bignum_param("p")); 
        let q = try!(self.get_bignum_param("q"));
        let dp = try!(self.get_bignum_param("dp"));
        let dq = try!(self.get_bignum_param("dq"));
        let qi = try!(self.get_bignum_param("qi"));
        
        Rsa::from_private_components(n, e, d, p, q, dp, dq, qi).map_err(JwtError::from)
    }
    
    fn is_private_key(&self) -> bool {
        self.params.contains_key("d")
    } 
}

#[derive(Clone, Debug)]
pub struct RsaSigner {
    private_key: Jwk,
    algorithms: Vec<Algorithm>
}

impl RsaSigner {
    pub fn new(private_key: Jwk) -> RsaSigner {
        RsaSigner {
            algorithms: compatible_algorithms(),
            private_key: private_key,
        }
    }
    
    fn sign_with_digest(d: hash::MessageDigest, private_key: &Jwk, input: &[u8]) -> JwtResult<Vec<u8>> {
        let rsa = try!(private_key.private_key());
        let pkey = try!(PKey::from_rsa(rsa));

        let mut signer = openssl::sign::Signer::new(d, &pkey).unwrap();

        //try!(signer.pkey_ctx_mut().set_rsa_padding(openssl::rsa::PKCS1_PADDING));
        try!(signer.update(input));

        let output = try!(signer.finish());

        Ok(output)
    }
}

impl Signer for RsaSigner {
    fn sign(&self, header: &Header, signing_input: &[u8]) -> JwtResult<String> {
        let result = try!(match header.alg {
            Algorithm::RS256 => Self::sign_with_digest(hash::MessageDigest::sha256(), &self.private_key, signing_input),
            Algorithm::RS384 => Self::sign_with_digest(hash::MessageDigest::sha384(), &self.private_key, signing_input),
            Algorithm::RS512 => Self::sign_with_digest(hash::MessageDigest::sha512(), &self.private_key, signing_input),
            _ => Err(JwtError::InvalidAlgorithm("algorithm is not a supported mac: ".to_owned(), header.alg))
        });
        
        Ok(result.to_base64(URL_SAFE))
    }
    
    fn has_algorithm(&self, a: Algorithm) -> bool {
        self.algorithms.contains(&a)
    }
}

pub fn compatible_algorithms() -> Vec<Algorithm> {
    vec![Algorithm::RS256, Algorithm::RS384, Algorithm::RS512]
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::Write;
    use serde;
    use rust_crypto::sha2::Sha256;
    use rust_crypto::digest::Digest;
    use openssl;
    
    use jwk::*;
    use json::*;
    use super::*;
    
    pub fn load_json<T: serde::Deserialize>(file_name: &str) -> T {
        let mut f = File::open(file_name).unwrap();
        
        f.read_json().unwrap()
    }
    
    #[test]
    pub fn test_rsa_sign_and_verify() {
        let key = load_json::<Jwk>("samples/jws/a2 - rs256/4-rsa-key.json");
        
        let public_key = key.public_key().unwrap();
        let private_key = key.private_key().unwrap();
        
        let message = load_json::<Vec<u8>>("samples/jws/a2 - rs256/3-signing-input-octets.json");

        let signer = RsaSigner::new(key.clone());

        let sig = RsaSigner::sign_with_digest(hash::MessageDigest::sha256(), &key, &message).unwrap();

        let expected_sig = load_json::<Vec<u8>>("samples/jws/a2 - rs256/5-signature-octets.json");

        assert_eq!(expected_sig, sig);
    }
    
    #[test]
    pub fn test_write_to_pem() {
        let key = load_json::<Jwk>("samples/jws/a2 - rs256/4-rsa-key.json");
        
        let public_key = key.public_key().unwrap();
        let private_key = key.private_key().unwrap();
        
        let mut buffer = File::create("key.pem").unwrap();
        let bytes = private_key.private_key_to_pem().unwrap();
        buffer.write_all(&bytes[..]).unwrap();
        buffer.flush().unwrap();
        
        let mut buffer = File::create("pubkey.pem").unwrap();
        let bytes = public_key.public_key_to_pem().unwrap();
        buffer.write_all(&bytes[..]).unwrap();
        buffer.flush().unwrap();
    }
}
use algorithm::Algorithm;
use result::{JwtError, JwtResult};
use header::Header;
use signer::Signer;
use rust_crypto::mac::{Mac, MacResult};
use rust_crypto::hmac::Hmac;
use rust_crypto::sha2::{Sha256, Sha384, Sha512};
use rust_crypto::digest::Digest;
use rustc_serialize::base64::*;

#[derive(Clone, Debug)]
pub struct MacSigner {
    secret: Vec<u8>,
    algorithms: Vec<Algorithm>
}

impl MacSigner {
    pub fn new<T: Into<Vec<u8>>>(secret: T) -> JwtResult<MacSigner> {
        let secret = secret.into();
        Ok(MacSigner {
            algorithms: compatible_algorithms(),
            secret: secret,
        })
    }
    
    fn sign_with_digest<D: Digest>(d: D, secret: &[u8], input: &[u8]) -> MacResult {
        let mut hmac = Hmac::new(d, secret);
        
        hmac.input(input);
        
        hmac.result()
    }
}

impl Signer for MacSigner {
    fn sign(&self, header: &Header, signing_input: &[u8]) -> JwtResult<String> {   
        let result = try!(match header.alg {
            Algorithm::HS256 => Ok(Self::sign_with_digest(Sha256::new(), &self.secret, signing_input)),
            Algorithm::HS384 => Ok(Self::sign_with_digest(Sha384::new(), &self.secret, signing_input)),
            Algorithm::HS512 => Ok(Self::sign_with_digest(Sha512::new(), &self.secret, signing_input)),
            _ => Err(JwtError::InvalidAlgorithm("algorithm is not a supported mac: ".to_owned(), header.alg))
        });
            
        Ok(result.code().to_base64(URL_SAFE))
    }
    
    fn has_algorithm(&self, a: Algorithm) -> bool {
        self.algorithms.contains(&a)
    }
}

pub fn compatible_algorithms() -> Vec<Algorithm> {
    vec![Algorithm::HS256, Algorithm::HS384, Algorithm::HS512]
}

#[cfg(test)]
mod test {
    use super::*;
    use signer::*;
    use algorithm::*;
    use header::*;
    use verifier::Verifier;
    
    #[test]
    fn sign_hs256() {
        let header = Header::new(Algorithm::HS256);
        let macsigner = MacSigner::new("secret".as_bytes()).unwrap();
        
        let result = macsigner.sign(&header, "hello world".as_bytes()).unwrap();
        let expected = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
        
        assert_eq!(result, expected);
    }

    #[test]
    fn verify_hs256() {
        let header = Header::new(Algorithm::HS256);
        let signer = MacSigner::new("secret".as_bytes()).unwrap();
        
        let sig = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
        
        let valid = signer.verify(&header, "hello world".as_bytes(), &sig).unwrap();
        
        assert!(valid);
    }
}
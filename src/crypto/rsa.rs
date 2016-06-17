use jwk::*;
use result::*;
use openssl::crypto::rsa::RSA;
use openssl::nid::Nid;
use openssl::bn::BigNum;
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

pub fn bn_to_b64(bn: BigNum) -> JwtResult<String> {
    use Part;

    let component = BigNumComponent(bn);
    component.to_base64().map_err(From::from)
}

pub trait RsaParameters {
    fn dp(&self) -> JwtResult<BigNum>;
    fn dq(&self) -> JwtResult<BigNum>;
    fn qi(&self) -> JwtResult<BigNum>;
}

impl RsaParameters for RSA {
    fn dp(&self) -> JwtResult<BigNum> {
        unsafe {
            BigNum::new_from_ffi((*self.as_ptr()).dmp1)
        }.map_err(From::from)
    }

    fn dq(&self) -> JwtResult<BigNum> {
        unsafe {
            BigNum::new_from_ffi((*self.as_ptr()).dmq1)
        }.map_err(From::from)
    }

    fn qi(&self) -> JwtResult<BigNum> {
        unsafe {
            BigNum::new_from_ffi((*self.as_ptr()).iqmp)
        }.map_err(From::from)
    }
}

pub trait RsaKey {
    fn convert_private_pem_to_jwk(self) -> JwtResult<Jwk>;

    fn convert_public_pem_to_jwk(self) -> JwtResult<Jwk>;
}

impl RsaKey for RSA {
    fn convert_private_pem_to_jwk(self) -> JwtResult<Jwk> {
        let mut vs = ValidationState::new();
    
        if !self.has_n() {
            vs.reject("n", ValidationError::MissingRequiredValue("n".to_owned()));
        }
    
        if !self.has_e() {
            vs.reject("e", ValidationError::MissingRequiredValue("e".to_owned()));
        }
    
        if vs.valid {
            let mut jwk = Jwk::new(KeyType::RSA);
        
            let n = try!(self.n());
            jwk.set_value("n", &try!(bn_to_b64(n)));
        
            let e = try!(self.e());
            jwk.set_value("e", &try!(bn_to_b64(e)));
        
            let d = try!(self.d());
            jwk.set_value("d", &try!(bn_to_b64(d)));
        
            let p = try!(self.p());
            jwk.set_value("p", &try!(bn_to_b64(p)));
        
            let q = try!(self.q());
            jwk.set_value("q", &try!(bn_to_b64(q)));
        
            let dp = try!(self.dp());
            jwk.set_value("dp", &try!(bn_to_b64(dp)));
        
            let dq = try!(self.dq());
            jwk.set_value("dq", &try!(bn_to_b64(dq)));
        
            let qi = try!(self.qi());
            jwk.set_value("qi", &try!(bn_to_b64(qi)));
        
            Ok(jwk)
        } else {
            Err(From::from(ValidationError::ValidationError(vs)))
        }
    }

    fn convert_public_pem_to_jwk(self) -> JwtResult<Jwk> {
        use Part;

        let mut vs = ValidationState::new();

        if !self.has_n() {
            vs.reject("n", ValidationError::MissingRequiredValue("n".to_owned()));
        }
    
        if !self.has_e() {
            vs.reject("e", ValidationError::MissingRequiredValue("e".to_owned()));
        }
    
        if vs.valid {
            let mut jwk = Jwk::new(KeyType::RSA);
        
            let n = try!(self.n());
            let n_bn = BigNumComponent(n);
            let n_b64 = try!(n_bn.to_base64());
            jwk.set_value("n", &n_b64);
        
            let e = try!(self.e());
            let e_bn = BigNumComponent(e);
            let e_b64 = try!(e_bn.to_base64());
            jwk.set_value("e", &e_b64);
        
            Ok(jwk)
        } else {
            Err(From::from(ValidationError::ValidationError(vs)))
        }
    }
}

pub trait RsaJwk {
    fn public_key(&self) -> JwtResult<RSA>;
    
    fn private_key(&self) -> JwtResult<RSA>;
    
    fn is_private_key(&self) -> bool;
}

impl RsaJwk for Jwk {
    fn public_key(&self) -> JwtResult<RSA> {
        let n = try!(self.get_bignum_param("n"));
        let e = try!(self.get_bignum_param("e"));        
        
        RSA::from_public_components(n, e).map_err(JwtError::from)
    }
    
    fn private_key(&self) -> JwtResult<RSA> {
        let n = try!(self.get_bignum_param("n"));
        let e = try!(self.get_bignum_param("e"));       
        let d = try!(self.get_bignum_param("d"));
        let p = try!(self.get_bignum_param("p")); 
        let q = try!(self.get_bignum_param("q"));
        let dp = try!(self.get_bignum_param("dp"));
        let dq = try!(self.get_bignum_param("dq"));
        let qi = try!(self.get_bignum_param("qi"));
        
        RSA::from_private_components(n, e, d, p, q, dp, dq, qi).map_err(JwtError::from)
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
    
    fn sign_with_digest<D: Digest>(mut d: D, nid: Nid, private_key: &Jwk, input: &[u8]) -> JwtResult<Vec<u8>> {
        let mut hash = vec![0;d.output_bytes()];
                
        d.input(&input);
        d.result(&mut hash);
        
        let rsa = try!(private_key.private_key());
        
        rsa.sign(nid, &hash).map_err(From::from)
    }
}

impl Signer for RsaSigner {
    fn sign(&self, header: &Header, signing_input: &[u8]) -> JwtResult<String> {
        let result = try!(match header.alg {
            Algorithm::RS256 => Self::sign_with_digest(Sha256::new(), Nid::SHA256, &self.private_key, signing_input),
            Algorithm::RS384 => Self::sign_with_digest(Sha384::new(), Nid::SHA256, &self.private_key, signing_input),
            Algorithm::RS512 => Self::sign_with_digest(Sha512::new(), Nid::SHA256, &self.private_key, signing_input),
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
        
        let mut sha = Sha256::new();
        sha.input(&message);
        let mut hash = vec![0;32];
        sha.result(&mut hash);
        
        println!("digest: {:?}", hash);
        
        let sig = private_key.sign(openssl::nid::Nid::SHA256, &hash).unwrap();
        
        println!("{:?}", sig);
        
        let verified = public_key.verify(openssl::nid::Nid::SHA256, &hash, &sig).unwrap();
        
        assert!(verified);
    }
    
    #[test]
    pub fn test_write_to_pem() {
        let key = load_json::<Jwk>("samples/jws/a2 - rs256/4-rsa-key.json");
        
        let public_key = key.public_key().unwrap();
        let private_key = key.private_key().unwrap();
        
        let mut buffer = File::create("key.pem").unwrap();
        private_key.private_key_to_pem(&mut buffer).unwrap();
        buffer.flush().unwrap();
        
        let mut buffer = File::create("pubkey.pem").unwrap();
        public_key.public_key_to_pem(&mut buffer).unwrap();
        buffer.flush().unwrap();
    }
}
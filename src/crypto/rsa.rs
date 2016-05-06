use jwk::*;
use result::*;
use openssl::crypto::rsa::RSA;

pub trait RsaKey {
    fn public_key(&self) -> JwtResult<RSA>;
    
    fn private_key(&self) -> JwtResult<RSA>;
}

impl RsaKey for Jwk {
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
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::{Read, Write};
    use serde_json;
    use serde;
    use rust_crypto::sha2::Sha256;
    use rust_crypto::digest::Digest;
    use openssl;
    
    use jwk::*;
    use super::*;
    
    pub fn read_file(name: &str) -> String {
        let mut f = File::open(name).unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        s
    }
    
    pub fn load_json<T: serde::Deserialize>(file_name: &str) -> T {
        let s = read_file(file_name);
        
        serde_json::de::from_str::<T>(&s).unwrap()
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
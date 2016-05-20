use openssl::bn::BigNum;
use std::ops::Deref;
use super::Part;
use result::JwtResult;
use rustc_serialize::base64::*;

pub struct BigNumComponent(pub BigNum);

impl Deref for BigNumComponent {
    type Target = BigNum;
    
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Into<BigNum> for BigNumComponent {    
    fn into(self) -> BigNum {
        self.0
    }
}

impl Part for BigNumComponent {
    type Encoded = String;
    
    fn to_base64(&self) -> JwtResult<String> {
        Ok(ToBase64::to_base64(&self.to_vec()[..], URL_SAFE))
    }
    
    fn from_base64<B: AsRef<[u8]>>(encoded: B) -> JwtResult<BigNumComponent> {
        let decoded = try!(encoded.as_ref().from_base64());
        let bn = try!(BigNum::new_from_slice(&decoded));
        Ok(BigNumComponent(bn))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use Part;
    
    #[test]
    fn test_bignum_base64() {
        let bn_b64 = "AQAB";
        let bn = BigNumComponent::from_base64(bn_b64.as_bytes()).unwrap();
        
        let result = bn.to_base64().unwrap();
        
        assert_eq!(result, bn_b64);
    }
}
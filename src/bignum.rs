use openssl::bn::BigNum;
use std::ops::Deref;
use super::Part;
use result::JwtResult;
use rustc_serialize::base64::*;

pub struct BigNumComponent(BigNum);

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
        self.to_vec().to_base64()
    }
    
    fn from_base64<B: AsRef<[u8]>>(encoded: B) -> JwtResult<BigNumComponent> {
        let decoded = try!(encoded.as_ref().from_base64());
        let bn = try!(BigNum::new_from_slice(&decoded));
        Ok(BigNumComponent(bn))
    }
}
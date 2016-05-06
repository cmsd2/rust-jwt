use std::collections::HashMap;
use std::result;

use rustc_serialize::base64::FromBase64;
use serde;
use serde::{Deserialize, Serializer, Deserializer};
use serde_json;
use openssl::bn::BigNum;

use key_type::*;
use result::*;

#[derive(Clone, Debug)]
pub struct Jwk {
    pub kty: KeyType,
    pub params: HashMap<String, serde_json::value::Value>,    
}

impl Jwk {
    pub fn get_param<'a>(&'a self, name: &str) -> JwtResult<&'a serde_json::value::Value> {
        self.params.get(name).ok_or(JwtError::MissingKeyParam(name.to_owned()))
    }
    
    pub fn set_param<T: Into<String>>(&mut self, name: T, value: serde_json::value::Value) -> () {
        self.params.insert(name.into(), value);
    }
    
    pub fn get_bignum_param(&self, name: &str) -> JwtResult<BigNum> {   
        let b64 = try!(self.get_param(name));
        
        let b64s = try!(b64.as_string().ok_or(JwtError::InvalidKeyParam(name.to_owned())));
        
        let octets = try!(b64s.from_base64());
        
        let bn = try!(BigNum::new_from_slice(&octets));
        
        Ok(bn)
    }
}

impl serde::Serialize for Jwk {
    fn serialize<S>(&self, serializer: &mut S) -> result::Result<(), S::Error>
        where S: serde::Serializer,
    {
        serializer.serialize_map(JwkSerVisitor::new(self))
    }
}

struct JwkSerVisitor<'a> {
    jwk: &'a Jwk
}

impl <'a> JwkSerVisitor<'a> {
    pub fn new(k: &'a Jwk) -> JwkSerVisitor<'a> {
        JwkSerVisitor {
            jwk: k
        }
    }
}

impl <'a> serde::ser::MapVisitor for JwkSerVisitor<'a> {
    fn visit<S>(&mut self, serializer: &mut S) -> result::Result<Option<()>, S::Error> where S: Serializer {
        try!(serializer.serialize_struct_elt("kty", self.jwk.kty));
        
        for (k,v) in &self.jwk.params {
            try!(serializer.serialize_map_elt(k, v));
        }
        
        Ok(None)
    }
    
    fn len(&self) -> Option<usize> {
        None
    }
}

impl serde::de::Deserialize for Jwk {
    fn deserialize<D>(deserializer: &mut D) -> result::Result<Jwk, D::Error>
        where D: serde::de::Deserializer
    {
        deserializer.deserialize(JwkVisitor)
    }
}

pub struct JwkVisitor;

impl serde::de::Visitor for JwkVisitor {
    type Value = Jwk;
    
    fn visit_map<V>(&mut self, mut visitor: V) -> result::Result<Jwk, V::Error>
        where V: serde::de::MapVisitor
    {
        let mut kty = None;
        let mut custom_params = HashMap::<String, serde_json::value::Value>::new();

        loop {
            if let Some(key) = try!(visitor.visit_key::<String>()) {
                match &key[..] {
                    "kty" => { kty = Some(try!(visitor.visit_value())); }
                    k => {
                        let v = try!(visitor.visit_value());
                    
                        custom_params.entry(k.to_owned()).or_insert(v); 
                    }
                }
            } else {
                break;
            }
        }

        let kty = match kty {
            Some(kty) => kty,
            None => try!(visitor.missing_field("kty")),
        };

        try!(visitor.end());

        Ok(Jwk{ 
            kty: kty,
            params: custom_params,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use key_type::*;
    use serde_json;
    
    #[test]
    pub fn test_kty_serialize() {
        let kty = KeyType::RSA;
        
        let s = serde_json::to_string(&kty).unwrap();
        
        assert_eq!(s, "\"RSA\"");
    }
    
    #[test]
    pub fn test_kty_deserialize() {
        let s = "\"RSA\"";
        
        let kty = serde_json::from_str::<KeyType>(s).unwrap();
        
        assert_eq!(kty, KeyType::RSA);
    }
}
use std::collections::BTreeMap;
use std;
use std::fmt;
use rustc_serialize::base64::FromBase64;
use serde;
use serde::{Deserialize, Serializer, Deserializer};
use serde::ser::SerializeMap;
use serde::de::Error;
use serde_json;
use openssl::bn::BigNum;
use bignum::*;
use super::*;
use json::*;
use key_type::*;
use result::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    pub fn new() -> JwkSet {
        JwkSet {
            keys: vec![],
        }
    }
}

#[derive(Clone, Debug)]
pub struct Jwk {
    pub kty: KeyType,
    pub params: BTreeMap<String, serde_json::value::Value>,    
}

impl Jwk {
    pub fn new(kty: KeyType) -> Jwk {
        Jwk {
            kty: kty,
            params: BTreeMap::new(),
        }
    }
    
    pub fn get_bignum_param(&self, name: &str) -> JwtResult<BigNum> {   
        let maybe_b64 = try!(self.get_value::<String>(name));
        
        let b64s = try!(maybe_b64.ok_or(JwtError::InvalidKeyParam(name.to_owned())));

        let bn = try!(BigNumComponent::from_base64(b64s));
        
        Ok(bn.into())
    }
}

impl JsonValueMap for Jwk {
    fn values<'a>(&'a self) -> &'a BTreeMap<String, serde_json::value::Value> {
        &self.params
    }
    
    fn values_mut<'a>(&'a mut self) -> &'a mut BTreeMap<String, serde_json::value::Value> {
        &mut self.params
    }
}

impl serde::Serialize for Jwk {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where S: serde::Serializer,
    {
        let mut map = try!(serializer.serialize_map(Some(self.params.len())));
        for (k,v) in &self.params {
            try!(map.serialize_key(k));
            try!(map.serialize_value(v));
        }

        map.end()
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

impl serde::de::Deserialize for Jwk {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Jwk, D::Error>
        where D: serde::de::Deserializer
    {
        deserializer.deserialize(JwkVisitor)
    }
}

pub struct JwkVisitor;

impl serde::de::Visitor for JwkVisitor {
    type Value = Jwk;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a jwk as a map from string to string")
    }
    
    fn visit_map<V>(self, mut visitor: V) -> std::result::Result<Jwk, V::Error>
        where V: serde::de::MapVisitor
    {
        let mut kty = None;
        let mut custom_params = BTreeMap::<String, serde_json::value::Value>::new();

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
            None => try!(Err(Error::missing_field("kty"))),
        };

        Ok(Jwk{ 
            kty: kty,
            params: custom_params,
        })
    }
}

#[cfg(test)]
mod test {
    
}
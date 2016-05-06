use serde::{Serialize, Deserialize};
use serde;
use serde_json;
use algorithm::*;
use std::collections::HashMap;

#[derive(Debug, PartialEq)]
/// A basic JWT header part, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional
pub struct Header {
    typ: String,
    pub alg: Algorithm,
    pub jku: Option<String>,
    pub kid: Option<String>,
    pub x5u: Option<String>,
    pub x5t: Option<String>,
    pub custom_params: HashMap<String, serde_json::value::Value>,
}

impl Header {
    pub fn new(algorithm: Algorithm) -> Header {
        Header {
            typ: "JWT".to_owned(),
            alg: algorithm,
            jku: None,
            kid: None,
            x5u: None,
            x5t: None,
            custom_params: HashMap::new(),
        }
    }
}

impl Default for Header {
    fn default() -> Header {
        Header::new(Algorithm::HS256)
    }
}

impl Serialize for Header {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer,
    {
        serializer.serialize_map(HeaderSerVisitor(&self))
    }
}

struct HeaderSerVisitor<'a>(&'a Header);

impl<'a> serde::ser::MapVisitor for HeaderSerVisitor<'a> {
    fn visit<S>(&mut self, serializer: &mut S) -> Result<Option<()>, S::Error>
        where S: serde::Serializer
    {
        try!(serializer.serialize_struct_elt("typ", &self.0.typ));
        try!(serializer.serialize_struct_elt("alg", &self.0.alg));
        
        if self.0.jku.is_some() {
            try!(serializer.serialize_struct_elt("jku", &self.0.jku));
        }
        
        if self.0.kid.is_some() {
            try!(serializer.serialize_struct_elt("kid", &self.0.kid));
        }
        
        if self.0.x5u.is_some() {
            try!(serializer.serialize_struct_elt("x5u", &self.0.x5u));
        }
        
        if self.0.x5t.is_some() {
            try!(serializer.serialize_struct_elt("x5t", &self.0.x5t));
        }
        
        for (k,v) in &self.0.custom_params {
            try!(serializer.serialize_map_elt(k, v));
        }
        
        Ok(None)
    }
}

impl Deserialize for Header {
    fn deserialize<D>(deserializer: &mut D) -> Result<Header, D::Error>
        where D: serde::Deserializer,
    {
        deserializer.deserialize(HeaderDeVisitor)
    }
}

struct HeaderDeVisitor;

impl serde::de::Visitor for HeaderDeVisitor {
    type Value = Header;

    fn visit_map<V>(&mut self, mut visitor: V) -> Result<Header, V::Error>
        where V: serde::de::MapVisitor,
    {
        let mut alg = None;
        let mut typ = None;
        let mut jku = None;
        let mut kid = None;
        let mut x5u = None;
        let mut x5t = None;
        let mut custom_params = HashMap::<String, serde_json::value::Value>::new();

        loop {
            if let Some(key) = try!(visitor.visit_key::<String>()) {
                match &key[..] {
                    "alg" => { alg = Some(try!(visitor.visit_value())); }
                    "typ" => { typ = Some(try!(visitor.visit_value())); }
                    "kid" => { kid = Some(try!(visitor.visit_value())); }
                    "jku" => { jku = Some(try!(visitor.visit_value())); }
                    "x5u" => { x5u = Some(try!(visitor.visit_value())); }
                    "x5t" => { x5t = Some(try!(visitor.visit_value())); }
                    k => {
                        let v = try!(visitor.visit_value());
                    
                        custom_params.entry(k.to_owned()).or_insert(v); 
                    }
                }
            } else {
                break;
            }
        }

        let alg = match alg {
            Some(alg) => alg,
            None => try!(visitor.missing_field("alg")),
        };
        
        let typ = match typ {
            Some(typ) => typ,
            None => try!(visitor.missing_field("typ")),
        };

        try!(visitor.end());

        Ok(Header{ 
            alg: alg,
            typ: typ,
            kid: kid,
            jku: jku,
            x5u: x5u,
            x5t: x5t,
            custom_params: custom_params,
        })
    }
}

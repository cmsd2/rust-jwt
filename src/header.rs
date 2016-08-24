use serde::{Serialize, Deserialize};
use serde;
use serde_json;
use algorithm::*;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq)]
/// A basic JWT header part, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional
pub struct Header {
    pub typ: Option<String>,
    pub alg: Algorithm,
    pub jku: Option<String>, // jwk key set url
    pub jwk: Option<String>, // json web key
    pub kid: Option<String>, // key id
    pub x5u: Option<String>, // x509 url
    pub x5c: Option<Vec<String>>, // x509 cert chain
    pub x5t: Option<String>, // x509 cert sha1 thumbprint
    pub x5t_s256: Option<String>, // x509 cert sha256 thumbprint
    pub cty: Option<String>, // payload media type
    pub crit: Option<Vec<String>>, // critical extension params list
    pub custom_params: HashMap<String, serde_json::value::Value>,
}

impl Header {
    pub fn new(algorithm: Algorithm) -> Header {
        Header {
            typ: Some("JWT".to_owned()),
            alg: algorithm,
            jku: None,
            jwk: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            cty: None,
            crit: None,
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
        let mut state = try!(serializer.serialize_map(None));

        if self.typ.is_some() {
            try!(serializer.serialize_map_key(&mut state, "typ"));
            try!(serializer.serialize_map_value(&mut state, &self.typ));
        }
        
        try!(serializer.serialize_map_key(&mut state, "alg"));
        try!(serializer.serialize_map_value(&mut state, &self.alg));
        
        if self.jku.is_some() {
            try!(serializer.serialize_map_key(&mut state, "jku"));
            try!(serializer.serialize_map_value(&mut state, &self.jku));
        }
        
        if self.jwk.is_some() {
            try!(serializer.serialize_map_key(&mut state, "jwk"));
            try!(serializer.serialize_map_value(&mut state, &self.jwk));
        }
        
        if self.kid.is_some() {
            try!(serializer.serialize_map_key(&mut state, "kid"));
            try!(serializer.serialize_map_value(&mut state, &self.kid));
        }
        
        if self.x5u.is_some() {
            try!(serializer.serialize_map_key(&mut state, "x5u"));
            try!(serializer.serialize_map_value(&mut state, &self.x5u));
        }
        
        if self.x5c.is_some() {
            try!(serializer.serialize_map_key(&mut state, "x5c"));
            try!(serializer.serialize_map_value(&mut state, &self.x5c));
        }
        
        if self.x5t.is_some() {
            try!(serializer.serialize_map_key(&mut state, "x5t"));
            try!(serializer.serialize_map_value(&mut state, &self.x5t));
        }
        
        if self.x5t_s256.is_some() {
            try!(serializer.serialize_map_key(&mut state, "x5t#s256"));
            try!(serializer.serialize_map_value(&mut state, &self.x5t_s256));
        }
        
        if self.cty.is_some() {
            try!(serializer.serialize_map_key(&mut state, "cty"));
            try!(serializer.serialize_map_value(&mut state, &self.cty));
        }
        
        if let Some(crit) = self.crit.as_ref() {
            if crit.len() != 0 {
                try!(serializer.serialize_map_key(&mut state, "crit"));
                try!(serializer.serialize_map_value(&mut state, &self.crit));
            }
        }
        
        for (k,v) in &self.custom_params {
            try!(serializer.serialize_map_key(&mut state, k));
            try!(serializer.serialize_map_value(&mut state, v));
        }
        
        serializer.serialize_map_end(state)
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
        let mut jwk = None;
        let mut kid = None;
        let mut x5u = None;
        let mut x5c = None;
        let mut x5t = None;
        let mut x5t_s256 = None;
        let mut cty = None;
        let mut crit = None;
        let mut custom_params = HashMap::<String, serde_json::value::Value>::new();

        loop {
            if let Some(key) = try!(visitor.visit_key::<String>()) {
                match &key[..] {
                    "alg" => { alg = Some(try!(visitor.visit_value())); }
                    "typ" => { typ = Some(try!(visitor.visit_value())); }
                    "kid" => { kid = Some(try!(visitor.visit_value())); }
                    "jku" => { jku = Some(try!(visitor.visit_value())); }
                    "jwk" => { jwk = Some(try!(visitor.visit_value())); }
                    "x5u" => { x5u = Some(try!(visitor.visit_value())); }
                    "x5c" => { x5c = Some(try!(visitor.visit_value())); }
                    "x5t" => { x5t = Some(try!(visitor.visit_value())); }
                    "x5t#s256" => { x5t_s256 = Some(try!(visitor.visit_value())); }
                    "cty" => { cty = Some(try!(visitor.visit_value())); }
                    "crit" => { crit = Some(try!(visitor.visit_value())); }
                    
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

        try!(visitor.end());

        Ok(Header{ 
            alg: alg,
            typ: typ,
            kid: kid,
            jku: jku,
            jwk: jwk,
            x5u: x5u,
            x5c: x5c,
            x5t: x5t,
            x5t_s256: x5t_s256,
            cty: cty,
            crit: crit,
            custom_params: custom_params,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json;
    
    #[test]
    fn test_header_serde() {
        let mut h = Header::default();
        h.jku = Some("https://example.com/jwk".to_owned());
        h.jwk = Some("".to_owned());
        h.kid = Some("one".to_owned());
        h.x5u = Some("https://example.com/x509cert".to_owned());
        h.x5c = Some(vec!["b64 jws cert".to_owned(), "b64 jws cert's CA etc".to_owned()]);
        h.x5t = Some("blah".to_owned());
        h.x5t_s256 = Some("blah256".to_owned());
        h.cty = Some("example".to_owned());
        h.crit = Some(vec!["exp".to_owned()]);
        h.custom_params.insert("exp".to_owned(), serde_json::to_value("soon"));
        
        let h_js = serde_json::to_string(&h).unwrap();
        
        let h2: Header = serde_json::from_str(&h_js).unwrap();
        
        assert_eq!(h, h2);
    }
}
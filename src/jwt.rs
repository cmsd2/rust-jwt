use std::collections::BTreeMap;
use std::result::Result;
use std::fmt;
use super::*;
use header::Header;
use claims::expiry::*;
use claims::not_before::*;
use result::{JwtError, JwtResult};
use chrono::*;
use serde;
use serde::{Serialize, Deserialize};
use serde::ser::SerializeMap;
use serde_json;
use cast;
use signer::Signer;
use verifier::Verifier;
use json::*;

pub type Jwt = TokenData<JwtClaims>;

impl Jwt {
    pub fn new(header: Header, claims: JwtClaims) -> Jwt {
        Jwt {
            header: header,
            claims: claims,
        }
    }
    
    /// Encode the claims passed and sign the payload using the algorithm from the header and the secret
    pub fn encode<S: Signer>(&self, signer: &S) -> JwtResult<String> {
        ::encode(self.header.clone(), &self.claims, signer)
    }

    /// Verify the signature using the header-specified algorithm and decode the json web token into headedr and claims.
    pub fn decode<V: Verifier>(token: &str, verifier: &V) -> JwtResult<Jwt> {
        ::decode(token, verifier)
    }

}

impl Default for Jwt {
    fn default() -> Jwt {
        Jwt::new(Header::default(), JwtClaims::new())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct JwtClaims {
    pub claims: BTreeMap<String, serde_json::value::Value>,
}

impl JwtClaims {
    pub fn new() -> JwtClaims {
        JwtClaims {
            claims: BTreeMap::new(),
        }
    }
}

impl JsonValueMap for JwtClaims {
    fn values<'a>(&'a self) -> &'a BTreeMap<String, serde_json::value::Value> {
        &self.claims
    }
    
    fn values_mut<'a>(&'a mut self) -> &'a mut BTreeMap<String, serde_json::value::Value> {
        &mut self.claims
    }
}

impl ExpiryClaim for JwtClaims {
    fn get_expiry_time(&self) -> JwtResult<Option<DateTime<UTC>>> {
        if let Some(exp) = self.claims.get("exp") {
            if exp.is_u64() {
                let seconds = exp.as_u64().unwrap();
                let dtresult = UTC.timestamp_opt(try!(cast::i64(seconds)), 0);
                
                if let LocalResult::Single(dt) = dtresult {
                    Ok(Some(dt))
                } else {
                    Err(JwtError::InvalidClaim("exp could not be converted to a datetime".to_string()))
                }
            } else {
                Err(JwtError::InvalidClaim("exp is not a datetime string".to_string()))
            }
        } else {
            Ok(None)
        }
    }
}

impl NotBeforeClaim for JwtClaims {
    fn get_not_before_time(&self) -> JwtResult<Option<DateTime<UTC>>> {
        if let Some(nbf) = self.claims.get("nbf") {
            if nbf.is_u64() {
                let seconds = nbf.as_u64().unwrap();
                let dtresult = UTC.timestamp_opt(try!(cast::i64(seconds)), 0);
                
                if let LocalResult::Single(dt) = dtresult {
                    Ok(Some(dt))
                } else {
                    Err(JwtError::InvalidClaim("nbf could not be converted to a datetime".to_string()))
                }
            } else {
                Err(JwtError::InvalidClaim("nbf is not a datetime string".to_string()))
            }
        } else {
            Ok(None)
        }
    }
}

impl Serialize for JwtClaims {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: serde::Serializer,
    {        
        let mut map = try!(serializer.serialize_map(Some(self.claims.len())));

        for (k,v) in &self.claims {
            try!(map.serialize_key(k));
            try!(map.serialize_value(v));
        }
        
        map.end()
    }
}

impl Deserialize for JwtClaims {
    fn deserialize<D>(deserializer: D) -> Result<JwtClaims, D::Error>
        where D: serde::Deserializer,
    {
        deserializer.deserialize(JwtClaimsDeVisitor)
    }
}

struct JwtClaimsDeVisitor;

impl serde::de::Visitor for JwtClaimsDeVisitor {
    type Value = JwtClaims;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a map from string to string")
    }

    fn visit_map<V>(self, mut visitor: V) -> Result<JwtClaims, V::Error>
        where V: serde::de::MapVisitor,
    {
        let mut claims = BTreeMap::<String, serde_json::value::Value>::new();

        loop {
            if let Some(key) = try!(visitor.visit_key::<String>()) {
                match &key[..] {
                    k => {
                        let v = try!(visitor.visit_value());
                    
                        claims.entry(k.to_owned()).or_insert(v); 
                    }
                }
            } else {
                break;
            }
        }

        Ok(JwtClaims{ 
            claims: claims,
        })
    }
}

#[cfg(test)]
mod test {
    use json::*;
    use super::*;
    use serde_json;
    use chrono::*;
    use claims::expiry::*;
    use claims::not_before::*;
    use claims::time::*;
    use validation::*;
    use crypto::mac_signer::MacSigner;
    
    #[test]
    fn test_header_serde() {
        let mut h = JwtClaims::new();
        h.set_value("exp", &UTC::now().timestamp());
        
        let h_js = serde_json::to_string(&h).unwrap();
        
        let h2: JwtClaims = serde_json::from_str(&h_js).unwrap();
        
        assert_eq!(h, h2);
    }
    
    #[test]
    fn test_claims_valid_in_server() {
        let now = UTC::now();
        
        let mut h = JwtClaims::new();
        h.set_value("exp", &now.timestamp());
        h.set_value("nbf", &now.timestamp());
        
        let mut vs = ValidationSchema::new();
        vs.rule(Box::new(ExpiryVerifier::new(SlowTimeProvider::new(FixedTimeProvider(now)))));
        vs.rule(Box::new(NotBeforeVerifier::new(SlowTimeProvider::new(FixedTimeProvider(now)))));
        
        assert!(vs.validate(&h).unwrap());
    }

    #[test]
    fn test_claims_invalid_in_server() {
        let now = UTC::now();
        
        let mut h = JwtClaims::new();
        h.set_value("exp", &now.checked_sub(Duration::minutes(10)).unwrap().timestamp());
        h.set_value("nbf", &now.checked_sub(Duration::minutes(10)).unwrap().timestamp());
        
        let mut vs = ValidationSchema::new();
        vs.rule(Box::new(ExpiryVerifier::new(SlowTimeProvider::new(FixedTimeProvider(now)))));
        vs.rule(Box::new(NotBeforeVerifier::new(SlowTimeProvider::new(FixedTimeProvider(now)))));
        
        assert!(false == vs.validate(&h).unwrap());
    }
    
    #[test]
    fn test_jwt_encode() {
        let now = UTC.timestamp(1462657679, 0);
        
        let mut j = Jwt::default();
        let signer = MacSigner::new("secret".as_bytes()).unwrap();
        
        j.claims.set_value("exp", &now.timestamp());
        j.claims.set_value("sub", &"b@b.com");

        let s = j.encode(&signer).unwrap();

        assert_eq!(s, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0NjI2NTc2NzksInN1YiI6ImJAYi5jb20ifQ.ukkwOH4BPNgykw7I7RI_hXNj1ZNH4BIErK0xD3tsM1M");
    }
    
    #[test]
    fn test_jwt_decode() {
        let signer = MacSigner::new("secret".as_bytes()).unwrap();
        
        let j = Jwt::decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0NjI2NTc2NzksInN1YiI6ImJAYi5jb20ifQ.ukkwOH4BPNgykw7I7RI_hXNj1ZNH4BIErK0xD3tsM1M", &signer).unwrap();
        
        assert_eq!(j.claims.get_value("exp").unwrap(), Some(1462657679i64));
        assert_eq!(j.claims.get_value("sub").unwrap(), Some("b@b.com".to_string()));
    }
}
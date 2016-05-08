use std::collections::BTreeMap;
use std::result::Result;
use super::*;
use header::Header;
use claims::expiry::*;
use claims::not_before::*;
use claims::ClaimsMap;
use result::{JwtError, JwtResult};
use chrono::*;
use serde;
use serde::{Serialize, Deserialize};
use serde_json;
use cast;
use signer::Signer;
use verifier::Verifier;

pub type Jwt = TokenData<JwtClaims>;

impl Jwt {
    pub fn new() -> Jwt {
        Jwt {
            header: Header::default(),
            claims: JwtClaims::new(),
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

impl ClaimsMap for JwtClaims {
    fn add_claim<S: Into<String>, V: serde::Serialize>(&mut self, name: S, value: &V) {
        self.claims.insert(name.into(), serde_json::value::to_value(value));
    }
    
    fn remove_claim(&mut self, name: &str) -> bool {
        self.claims.remove(name).is_some()
    }
    
    fn has_claim(&self, name: &str) -> bool {
        self.claims.contains_key(name)
    }
    
    fn get_claim<C: serde::Deserialize>(&self, name: &str) -> JwtResult<Option<C>> {
        if let Some(claim) = self.claims.get(name) {
            let v = try!(serde_json::value::from_value(claim.clone()));
            
            Ok(Some(v))
        } else {
            Ok(None)
        }
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
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer,
    {
        serializer.serialize_map(JwtClaimsSerVisitor(&self))
    }
}

struct JwtClaimsSerVisitor<'a>(&'a JwtClaims);

impl<'a> serde::ser::MapVisitor for JwtClaimsSerVisitor<'a> {
    fn visit<S>(&mut self, serializer: &mut S) -> Result<Option<()>, S::Error>
        where S: serde::Serializer
    {        
        for (k,v) in &self.0.claims {
            try!(serializer.serialize_map_elt(k, v));
        }
        
        Ok(None)
    }
}

impl Deserialize for JwtClaims {
    fn deserialize<D>(deserializer: &mut D) -> Result<JwtClaims, D::Error>
        where D: serde::Deserializer,
    {
        deserializer.deserialize(JwtClaimsDeVisitor)
    }
}

struct JwtClaimsDeVisitor;

impl serde::de::Visitor for JwtClaimsDeVisitor {
    type Value = JwtClaims;

    fn visit_map<V>(&mut self, mut visitor: V) -> Result<JwtClaims, V::Error>
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

        try!(visitor.end());

        Ok(JwtClaims{ 
            claims: claims,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json;
    use chrono::*;
    use claims::expiry::*;
    use claims::not_before::*;
    use claims::time::*;
    use claims::ClaimsMap;
    use rbvt::validation::*;
    use crypto::mac_signer::MacSigner;
    
    #[test]
    fn test_header_serde() {
        let mut h = JwtClaims::new();
        h.add_claim("exp", &UTC::now().timestamp());
        
        let h_js = serde_json::to_string(&h).unwrap();
        
        let h2: JwtClaims = serde_json::from_str(&h_js).unwrap();
        
        assert_eq!(h, h2);
    }
    
    #[test]
    fn test_claims_valid() {
        let now = UTC::now();
        
        let mut h = JwtClaims::new();
        h.add_claim("exp", &now.timestamp());
        h.add_claim("nbf", &now.timestamp());
        
        let mut vs = ValidationSchema::new();
        vs.rule(Box::new(ExpiryVerifier::new(FixedTimeProvider(now))));
        vs.rule(Box::new(NotBeforeVerifier::new(FixedTimeProvider(now))));
        
        assert!(vs.validate(&h).unwrap());
    }
    
    #[test]
    fn test_jwt_encode() {
        let now = UTC.timestamp(1462657679, 0);
        
        let mut j = Jwt::new();
        let signer = MacSigner::new("secret".as_bytes()).unwrap();
        
        j.claims.add_claim("exp", &now.timestamp());
        j.claims.add_claim("sub", &"b@b.com");

        let s = j.encode(&signer).unwrap();

        assert_eq!(s, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0NjI2NTc2NzksInN1YiI6ImJAYi5jb20ifQ.ukkwOH4BPNgykw7I7RI_hXNj1ZNH4BIErK0xD3tsM1M");
    }
    
    #[test]
    fn test_jwt_decode() {
        let signer = MacSigner::new("secret".as_bytes()).unwrap();
        
        let j = Jwt::decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0NjI2NTc2NzksInN1YiI6ImJAYi5jb20ifQ.ukkwOH4BPNgykw7I7RI_hXNj1ZNH4BIErK0xD3tsM1M", &signer).unwrap();
        
        assert_eq!(j.claims.claims.get("exp"), Some(serde_json::to_value(&1462657679)).as_ref());
        assert_eq!(j.claims.claims.get("sub"), Some(serde_json::to_value("b@b.com")).as_ref());
    }
}
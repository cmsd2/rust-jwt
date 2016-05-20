use std::result::Result as CoreResult;
use std::fmt;
use serde;
use result::{JwtResult, JwtError};

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Algorithm {
    None,
    
    HS256,
    HS384,
    HS512,
    
    RS256,
    RS384,
    RS512,
    
    ES256,
    ES384,
    ES512,
    
    PS256,
    PS384,
    PS512,
}

pub static JWS_ALGORITHMS: &'static [Algorithm] = &[
    Algorithm::HS256, Algorithm::HS384, Algorithm::HS512,
    Algorithm::RS256, Algorithm::RS384, Algorithm::RS512,
    Algorithm::ES256, Algorithm::ES384, Algorithm::ES512,
    Algorithm::PS256, Algorithm::PS384, Algorithm::PS512,
];

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Algorithm::None => write!(f, "none"),
            
            Algorithm::HS256 => write!(f, "HS256"),
            Algorithm::HS384 => write!(f, "HS384"),
            Algorithm::HS512 => write!(f, "HS512"),
            
            Algorithm::RS256 => write!(f, "RS256"),
            Algorithm::RS384 => write!(f, "RS384"),
            Algorithm::RS512 => write!(f, "RS512"),
            
            Algorithm::ES256 => write!(f, "ES256"),
            Algorithm::ES384 => write!(f, "ES384"),
            Algorithm::ES512 => write!(f, "ES512"),
            
            Algorithm::PS256 => write!(f, "PS256"),
            Algorithm::PS384 => write!(f, "PS384"),
            Algorithm::PS512 => write!(f, "PS512"),
        }
    }
}

impl Algorithm {
    pub fn from_str(s: &str) -> JwtResult<Algorithm> {
        match s {
            "none" => Ok(Algorithm::None),
            
            "HS256" => Ok(Algorithm::HS256),
            "HS384" => Ok(Algorithm::HS384),
            "HS512" => Ok(Algorithm::HS512),
            
            "RS256" => Ok(Algorithm::RS256),
            "RS384" => Ok(Algorithm::RS384),
            "RS512" => Ok(Algorithm::RS512),
            
            "ES256" => Ok(Algorithm::ES256),
            "ES384" => Ok(Algorithm::ES384),
            "ES512" => Ok(Algorithm::ES512),
            
            "PS256" => Ok(Algorithm::PS256),
            "PS384" => Ok(Algorithm::PS384),
            "PS512" => Ok(Algorithm::PS512),
            
            _ => Err(JwtError::BadArgument(format!("unknown algorithm: {}", s)))
        }
    }
}

impl serde::Serialize for Algorithm {
    fn serialize<S>(&self, serializer: &mut S) -> CoreResult<(), S::Error>
        where S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{}", self))
    }
}

impl serde::de::Deserialize for Algorithm {
    fn deserialize<D>(deserializer: &mut D) -> Result<Algorithm, D::Error>
        where D: serde::de::Deserializer
    {
        deserializer.deserialize(AlgorithmVisitor)
    }
}

pub struct AlgorithmVisitor;

impl serde::de::Visitor for AlgorithmVisitor {
    type Value = Algorithm;
    
    fn visit_str<E>(&mut self, s: &str) -> Result<Algorithm, E> where E: serde::Error
    {
        match s {
            "none" => Ok(Algorithm::None),
            
            "HS256" => Ok(Algorithm::HS256),
            "HS384" => Ok(Algorithm::HS384),
            "HS512" => Ok(Algorithm::HS512),
            
            "RS256" => Ok(Algorithm::RS256),
            "RS384" => Ok(Algorithm::RS384),
            "RS512" => Ok(Algorithm::RS512),
            
            "ES256" => Ok(Algorithm::ES256),
            "ES384" => Ok(Algorithm::ES384),
            "ES512" => Ok(Algorithm::ES512),
            
            "PS256" => Ok(Algorithm::PS256),
            "PS384" => Ok(Algorithm::PS384),
            "PS512" => Ok(Algorithm::PS512),
            
            _ => Err(serde::de::Error::custom("unrecognised algorithm"))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json;
    
    #[test]
    pub fn test_alg_serialize() {
        let alg = Algorithm::HS256;
        
        let s = serde_json::to_string(&alg).unwrap();
        
        assert_eq!(s, "\"HS256\"");
    }
    
    #[test]
    pub fn test_alg_deserialize() {
        let s = "\"HS256\"";
        
        let alg = serde_json::from_str::<Algorithm>(s).unwrap();
        
        assert_eq!(alg, Algorithm::HS256);
    }
}
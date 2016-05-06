use std::fmt;
use std::result;

use serde;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum KeyType {
    RSA,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeyType::RSA => write!(f, "RSA"),
        }
    }
}

impl serde::Serialize for KeyType {
    fn serialize<S>(&self, serializer: &mut S) -> result::Result<(), S::Error>
        where S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{}", self))
    }
}

impl serde::de::Deserialize for KeyType {
    fn deserialize<D>(deserializer: &mut D) -> result::Result<KeyType, D::Error>
        where D: serde::de::Deserializer
    {
        deserializer.deserialize(KeyTypeVisitor)
    }
}

pub struct KeyTypeVisitor;

impl serde::de::Visitor for KeyTypeVisitor {
    type Value = KeyType;
    
    fn visit_str<E>(&mut self, s: &str) -> Result<KeyType, E> where E: serde::Error
    {
        match s {
            "RSA" => Ok(KeyType::RSA),
            
            _ => Err(serde::de::Error::custom("unrecognised key type"))
        }
    }
}
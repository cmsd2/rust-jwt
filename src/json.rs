use std::collections::BTreeMap;
use serde_json;
use serde;
use result::JwtResult;

pub trait JsonValueMap {
    fn values<'a>(&'a self) -> &'a BTreeMap<String, serde_json::value::Value>;
    fn values_mut<'a>(&'a mut self) -> &'a mut BTreeMap<String, serde_json::value::Value>;
}

pub trait JsonValueMapAccessors {
    fn get_json_value<'a>(&'a self, name: &str) -> Option<&'a serde_json::value::Value>;
    fn set_json_value<T: Into<String>>(&mut self, name: T, value: serde_json::value::Value) -> ();
    fn set_value<S: Into<String>, V: serde::Serialize>(&mut self, name: S, value: &V);
    fn remove_value(&mut self, name: &str) -> bool;
    fn has_value(&self, name: &str) -> bool;
    fn get_value<C: serde::Deserialize>(&self, name: &str) -> JwtResult<Option<C>>;
}

impl <M> JsonValueMapAccessors for M where M: JsonValueMap {
    fn get_json_value<'a>(&'a self, name: &str) -> Option<&'a serde_json::value::Value> {
        self.values().get(name)
    }
    
    fn set_json_value<T: Into<String>>(&mut self, name: T, value: serde_json::value::Value) -> () {
        self.values_mut().insert(name.into(), value);
    }
    
    fn set_value<S: Into<String>, V: serde::Serialize>(&mut self, name: S, value: &V) {
        self.values_mut().insert(name.into(), serde_json::value::to_value(value));
    }
    
    fn remove_value(&mut self, name: &str) -> bool {
        self.values_mut().remove(name).is_some()
    }
    
    fn has_value(&self, name: &str) -> bool {
        self.values().contains_key(name)
    }
    
    fn get_value<C: serde::Deserialize>(&self, name: &str) -> JwtResult<Option<C>> {
        if let Some(value) = self.values().get(name) {
            let v = try!(serde_json::value::from_value(value.clone()));
            
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }
}

use serde;
use result::JwtResult;
use rbvt::validation::*;

pub mod time;
pub mod expiry;
pub mod not_before;

pub trait ClaimsMap {
    fn add_claim<S: Into<String>, V: serde::Serialize>(&mut self, name: S, value: &V);
    
    fn remove_claim(&mut self, name: &str) -> bool;
    
    fn has_claim(&self, name: &str) -> bool;
    
    fn get_claim<C: serde::Deserialize>(&self, name: &str) -> JwtResult<Option<C>>;
}

pub fn claims_verifier<C>() -> ValidationSchema<C> where C: expiry::ExpiryClaim + not_before::NotBeforeClaim + 'static {
    let mut vs: ValidationSchema<C> = ValidationSchema::new();
    
    vs.rule(Box::new(expiry::ExpiryVerifier::new(time::SystemTimeProvider)));
    vs.rule(Box::new(not_before::NotBeforeVerifier::new(time::SystemTimeProvider)));
        
    vs
}

#[cfg(test)]
mod test {
    use super::*;
    use jwt::*;
    use rbvt::validation::*;
    
    #[test]
    fn simple_verify_should_compile_and_not_panic() {
        let claims = JwtClaims::new();
        
        let mut vs = claims_verifier::<JwtClaims>();
        
        vs.validate(&claims).unwrap();
    }
}
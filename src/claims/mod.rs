use validation::*;

pub mod time;
pub mod expiry;
pub mod not_before;

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
    use validation::*;
    
    #[test]
    fn simple_verify_should_compile_and_not_panic() {
        let claims = JwtClaims::new();
        
        let mut vs = claims_verifier::<JwtClaims>();
        
        vs.validate(&claims).unwrap();
    }
}
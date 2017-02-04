use validation::*;

pub mod time;
pub mod expiry;
pub mod not_before;

/// Constructs a set of validation rules for the
/// exp and nbf claims for the type being validated.
/// Use a `SlowTimeProvider` for the `exp_tp` `TimeProvider`
/// to allow a grace period on the exp claim.
/// Use a `FastTimeProvider` for the `nbf_tp` `TimeProvider`
/// to allow a grace period on the nbf claim.
pub fn claims_verifier<C,T1,T2>(exp_tp: T1, nbf_tp: T2) -> ValidationSchema<C> 
        where C: expiry::ExpiryClaim + not_before::NotBeforeClaim + 'static,
              T1: time::TimeProvider + Clone + 'static,
              T2: time::TimeProvider + Clone + 'static {
    let mut vs: ValidationSchema<C> = ValidationSchema::new();
    
    vs.rule(Box::new(expiry::ExpiryVerifier::new(exp_tp)));
    vs.rule(Box::new(not_before::NotBeforeVerifier::new(nbf_tp)));
        
    vs
}

#[cfg(test)]
mod test {
    use super::*;
    use jwt::*;
    use validation::*;
    use claims::time::*;
    use chrono::*;
    
    #[test]
    fn simple_verify_should_compile_and_not_panic() {
        let claims = JwtClaims::new();
        
        let mut vs: ValidationSchema<JwtClaims> = claims_verifier(
                SlowTimeProvider::new(FixedTimeProvider(UTC::now())),
                FastTimeProvider::new(FixedTimeProvider(UTC::now())));
        
        vs.validate(&claims).unwrap();
    }
}
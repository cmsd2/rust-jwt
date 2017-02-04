use validation::*;
use ::time::Duration;

pub mod time;
pub mod expiry;
pub mod not_before;

/// Constructs a set of validation rules for the
/// exp and nbf claims for the type being validated.
/// Pass in exp and nbf claim grace period durations to adjust time comparisons.
/// Use positive grace periods to be lenient.
/// Use negative grace periods e.g. to renew tokens ahead of time.
pub fn claims_verifier<C,T>(tp: T, exp_grace: Duration, nbf_grace: Duration) -> ValidationSchema<C> 
        where C: expiry::ExpiryClaim + not_before::NotBeforeClaim + 'static,
              T: time::TimeProvider + Clone + 'static {
    let mut vs: ValidationSchema<C> = ValidationSchema::new();
    
    vs.rule(Box::new(expiry::ExpiryVerifier::new(tp.clone(), exp_grace)));
    vs.rule(Box::new(not_before::NotBeforeVerifier::new(tp, nbf_grace)));
        
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
        let now = UTC::now();
        let tp = FixedTimeProvider(now);
        let claims = JwtClaims::new();
        
        let mut vs: ValidationSchema<JwtClaims> = claims_verifier(tp, Duration::zero(), Duration::zero());
        
        vs.validate(&claims).unwrap();
    }
}
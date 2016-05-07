use std::sync::Arc;
use std::marker::PhantomData;
use chrono::*;
use super::time::*;
use result::JwtResult;
use rbvt::result::ValidationError;
use rbvt::validation::*;
use rbvt::state::*;
use rbvt;

pub trait ExpiryClaim {
    fn get_expiry_time(&self) -> JwtResult<Option<DateTime<UTC>>>;
}

pub struct ExpiryVerifier<C: ExpiryClaim, T: SkewedTimeProvider> {
    time_provider: T,
    phantom: PhantomData<C>,
}

impl<C: ExpiryClaim, T: SkewedTimeProvider> ExpiryVerifier<C, T> {
    pub fn new(time_provider: T) -> ExpiryVerifier<C, T> {
        ExpiryVerifier {
            time_provider: time_provider,
            phantom: PhantomData,
        }
    }
}

impl<C: ExpiryClaim, T: SkewedTimeProvider> Rule<C, ValidationState> for ExpiryVerifier<C, T> {
    fn validate(&self, c: &C, state: &mut ValidationState) -> rbvt::result::Result<()> {
        let now_plus_a_bit = try!(self.time_provider.now_utc_minus_a_bit().map_err(|e| ValidationError::Error(Arc::new(Box::new(e)))));
    
        if let Some(expiry) = try!(c.get_expiry_time().map_err(|e| ValidationError::Error(Arc::new(Box::new(e))))) {
            if now_plus_a_bit.ge(&expiry) {
                state.reject("exp", ValidationError::InvalidValue("token has expired".to_owned()));
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use rbvt::validation::*;
    use claims::time::*;
    use chrono::*;
    use result::JwtResult;
    use super::*;
    
    struct TestClaim(Option<DateTime<UTC>>);
    impl ExpiryClaim for TestClaim {
        fn get_expiry_time(&self) -> JwtResult<Option<DateTime<UTC>>> {
            Ok(self.0)
        }
    }
    
    #[test]
    fn test_almost_expired() {
        let now = UTC::now();
        let tp = FixedTimeProvider(now);
        let c = TestClaim(now.checked_add(Duration::seconds(10)));
        
        let mut vs = ValidationSchema::new();
        vs.rule(Box::new(ExpiryVerifier::new(tp)));
        
        assert!(vs.validate(&c).unwrap());
    }
    
    #[test]
    fn test_not_expired() {
        let now = UTC::now();
        let tp = FixedTimeProvider(now);
        let c = TestClaim(now.checked_add(Duration::minutes(10)));
        
        let mut vs = ValidationSchema::new();
        vs.rule(Box::new(ExpiryVerifier::new(tp)));
        
        assert!(vs.validate(&c).unwrap());
    }
    
    #[test]
    fn test_would_have_just_expired() {
        let now = UTC::now();
        let tp = FixedTimeProvider(now);
        let c = TestClaim(now.checked_sub(Duration::seconds(10)));
        
        let mut vs = ValidationSchema::new();
        vs.rule(Box::new(ExpiryVerifier::new(tp)));
        
        assert!(vs.validate(&c).unwrap());
    }
    
    #[test]
    fn test_just_expired() {
        let now = UTC::now();
        let tp = FixedTimeProvider(now);
        let c = TestClaim(now.checked_sub(Duration::minutes(1)));
        
        let mut vs = ValidationSchema::new();
        vs.rule(Box::new(ExpiryVerifier::new(tp)));
        
        assert!(false == vs.validate(&c).unwrap());
    }
    
    #[test]
    fn test_definitely_expired() {
        let now = UTC::now();
        let tp = FixedTimeProvider(now);
        let c = TestClaim(now.checked_sub(Duration::minutes(10)));
        
        let mut vs = ValidationSchema::new();
        vs.rule(Box::new(ExpiryVerifier::new(tp)));
        
        assert!(false == vs.validate(&c).unwrap());
    }
}
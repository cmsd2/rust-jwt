use std::sync::Arc;
use std::marker::PhantomData;
use chrono::*;
use super::time::*;
use result::JwtResult;
use validation::*;

pub trait NotBeforeClaim {
    fn get_not_before_time(&self) -> JwtResult<Option<DateTime<UTC>>>;
}

pub struct NotBeforeVerifier<C: NotBeforeClaim, T: SkewedTimeProvider> {
    time_provider: T,
    phantom: PhantomData<C>,
}

impl<C: NotBeforeClaim, T: SkewedTimeProvider> NotBeforeVerifier<C, T> {
    pub fn new(time_provider: T) -> NotBeforeVerifier<C, T> {
        NotBeforeVerifier {
            time_provider: time_provider,
            phantom: PhantomData,
        }
    }
}

impl<C: NotBeforeClaim, T: SkewedTimeProvider> Rule<C, ValidationState> for NotBeforeVerifier<C, T> {
    fn validate(&self, c: &C, state: &mut ValidationState) -> ValidationResult<()> {
        let now_plus_a_bit = try!(self.time_provider.now_utc_plus_a_bit().map_err(|e| ValidationError::Error(Arc::new(Box::new(e)))));
    
        if let Some(not_before_time) = try!(c.get_not_before_time().map_err(|e| ValidationError::Error(Arc::new(Box::new(e))))) {
            if now_plus_a_bit.lt(&not_before_time) {
                state.reject("nbf", ValidationError::InvalidValue("token is not yet valid".to_owned()));
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use validation::*;
    use claims::time::*;
    use chrono::*;
    use result::JwtResult;
    use super::*;
    
    struct TestClaim(Option<DateTime<UTC>>);
    impl NotBeforeClaim for TestClaim {
        fn get_not_before_time(&self) -> JwtResult<Option<DateTime<UTC>>> {
            Ok(self.0)
        }
    }
    
    #[test]
    fn test_just_valid() {
        let now = UTC::now();
        let tp = FixedTimeProvider(now);
        let c = TestClaim(now.checked_sub(Duration::seconds(10)));
        
        let mut vs = ValidationSchema::new();
        vs.rule(Box::new(NotBeforeVerifier::new(tp)));
        
        assert!(vs.validate(&c).unwrap());
    }
    
    #[test]
    fn test_valid() {
        let now = UTC::now();
        let tp = FixedTimeProvider(now);
        let c = TestClaim(now.checked_sub(Duration::minutes(10)));
        
        let mut vs = ValidationSchema::new();
        vs.rule(Box::new(NotBeforeVerifier::new(tp)));
        
        assert!(vs.validate(&c).unwrap());
    }
    
    #[test]
    fn test_would_have_been_invalid() {
        let now = UTC::now();
        let tp = FixedTimeProvider(now);
        let c = TestClaim(now.checked_add(Duration::seconds(10)));
        
        let mut vs = ValidationSchema::new();
        vs.rule(Box::new(NotBeforeVerifier::new(tp)));
        
        assert!(vs.validate(&c).unwrap());
    }
    
    #[test]
    fn test_on_the_line() {
        let now = UTC::now();
        let tp = FixedTimeProvider(now);
        let c = TestClaim(now.checked_add(Duration::seconds(60)));
        
        let mut vs = ValidationSchema::new();
        vs.rule(Box::new(NotBeforeVerifier::new(tp)));
        
        assert!(vs.validate(&c).unwrap());
    }
    
    #[test]
    fn test_definitely_invalid() {
        let now = UTC::now();
        let tp = FixedTimeProvider(now);
        let c = TestClaim(now.checked_add(Duration::minutes(10)));
        
        let mut vs = ValidationSchema::new();
        vs.rule(Box::new(NotBeforeVerifier::new(tp)));
        
        assert!(false == vs.validate(&c).unwrap());
    }
}
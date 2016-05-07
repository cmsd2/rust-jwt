use chrono::*;
use result::{JwtError, JwtResult};

pub trait TimeProvider {
    fn now_utc(&self) -> DateTime<UTC>;
    
    fn max_clock_skew(&self) -> Duration;
}

pub trait SkewedTimeProvider : TimeProvider {
    fn now_utc_plus_a_bit(&self) -> JwtResult<DateTime<UTC>>;
    
    fn now_utc_minus_a_bit(&self) -> JwtResult<DateTime<UTC>>;
}

impl<T> SkewedTimeProvider for T where T: TimeProvider {
    fn now_utc_plus_a_bit(&self) -> JwtResult<DateTime<UTC>> {
        let now = self.now_utc();
        let max_skew = self.max_clock_skew();
    
        let now_plus_a_bit = try!(now.checked_add(max_skew).ok_or(JwtError::BadArgument("max clock skew too large".to_owned())));

        Ok(now_plus_a_bit)
    }
    
    fn now_utc_minus_a_bit(&self) -> JwtResult<DateTime<UTC>> {
        let now = self.now_utc();
        let max_skew = self.max_clock_skew();
    
        let now_minus_a_bit = try!(now.checked_sub(max_skew).ok_or(JwtError::BadArgument("max clock skew too large".to_owned())));

        Ok(now_minus_a_bit)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct SystemTimeProvider;

impl TimeProvider for SystemTimeProvider {
    fn now_utc(&self) -> DateTime<UTC> {
        UTC::now()
    }
    
    fn max_clock_skew(&self) -> Duration {
        Duration::minutes(1)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct FixedTimeProvider(pub DateTime<UTC>);

impl TimeProvider for FixedTimeProvider {
    fn now_utc(&self) -> DateTime<UTC> {
        self.0
    }
    
    fn max_clock_skew(&self) -> Duration {
        Duration::minutes(1)
    }
}
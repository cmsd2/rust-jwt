use chrono::*;
use result::{JwtError, JwtResult};

pub trait TimeProvider {
    fn now_utc(&self) -> JwtResult<DateTime<UTC>>;
    
    fn max_clock_skew(&self) -> Duration;
}

pub trait SkewedTimeProvider : TimeProvider {
    fn now_utc_plus_duration(&self, d: Duration) -> JwtResult<DateTime<UTC>>;

    fn now_utc_plus_a_bit(&self) -> JwtResult<DateTime<UTC>>;
    
    fn now_utc_minus_a_bit(&self) -> JwtResult<DateTime<UTC>>;
}

impl<T> SkewedTimeProvider for T where T: TimeProvider {
    fn now_utc_plus_duration(&self, d: Duration) -> JwtResult<DateTime<UTC>> {
        let now = try!(self.now_utc());

        let now_plus_a_bit = try!(now.checked_add(d)
                .ok_or(JwtError::BadArgument("datetime addition overflow".to_owned())));

        Ok(now_plus_a_bit)
    }

    fn now_utc_plus_a_bit(&self) -> JwtResult<DateTime<UTC>> {
        self.now_utc_plus_duration(self.max_clock_skew())
    }
    
    fn now_utc_minus_a_bit(&self) -> JwtResult<DateTime<UTC>> {
        self.now_utc_plus_duration(-self.max_clock_skew())
    }
}

#[derive(Copy, Clone, Debug)]
pub struct SystemTimeProvider;

impl TimeProvider for SystemTimeProvider {
    fn now_utc(&self) -> JwtResult<DateTime<UTC>> {
        Ok(UTC::now())
    }
    
    fn max_clock_skew(&self) -> Duration {
        Duration::minutes(1)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct FixedTimeProvider(pub DateTime<UTC>);

impl TimeProvider for FixedTimeProvider {
    fn now_utc(&self) -> JwtResult<DateTime<UTC>> {
        Ok(self.0)
    }
    
    fn max_clock_skew(&self) -> Duration {
        Duration::minutes(1)
    }
}
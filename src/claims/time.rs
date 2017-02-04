use chrono::*;
use result::{JwtError, JwtResult};

pub trait TimeProvider {
    fn now_utc(&self) -> JwtResult<DateTime<UTC>>;
    
    fn max_clock_skew(&self) -> Duration;
}

#[derive(Clone)]
pub struct SlowTimeProvider<T> where T: TimeProvider + Clone + 'static {
    base: T
}

impl <T> SlowTimeProvider<T> where T: TimeProvider + Clone + 'static {
    pub fn new(tp: T) -> SlowTimeProvider<T> {
        SlowTimeProvider {
            base: tp
        }
    }
}

impl <T> TimeProvider for SlowTimeProvider<T> where T: TimeProvider + Clone + 'static {
    fn now_utc(&self) -> JwtResult<DateTime<UTC>> {
        self.base.now_utc_minus_a_bit()
    }

    fn max_clock_skew(&self) -> Duration {
        self.base.max_clock_skew()
    }
}

#[derive(Clone)]
pub struct FastTimeProvider<T> where T: TimeProvider + Clone + 'static {
    base: T
}

impl <T> FastTimeProvider<T> where T: TimeProvider + Clone + 'static {
    pub fn new(tp: T) -> FastTimeProvider<T> {
        FastTimeProvider {
            base: tp
        }
    }
}

impl <T> TimeProvider for FastTimeProvider<T> where T: TimeProvider + Clone + 'static {
    fn now_utc(&self) -> JwtResult<DateTime<UTC>> {
        self.base.now_utc_plus_a_bit()
    }

    fn max_clock_skew(&self) -> Duration {
        self.base.max_clock_skew()
    }
}

pub trait SkewedTimeProvider : TimeProvider {
    fn now_utc_plus_a_bit(&self) -> JwtResult<DateTime<UTC>>;
    
    fn now_utc_minus_a_bit(&self) -> JwtResult<DateTime<UTC>>;
}

impl<T> SkewedTimeProvider for T where T: TimeProvider {
    fn now_utc_plus_a_bit(&self) -> JwtResult<DateTime<UTC>> {
        let now = try!(self.now_utc());
        let max_skew = self.max_clock_skew();
    
        let now_plus_a_bit = try!(now.checked_add(max_skew).ok_or(JwtError::BadArgument("max clock skew too large".to_owned())));

        Ok(now_plus_a_bit)
    }
    
    fn now_utc_minus_a_bit(&self) -> JwtResult<DateTime<UTC>> {
        let now = try!(self.now_utc());
        let max_skew = self.max_clock_skew();
    
        let now_minus_a_bit = try!(now.checked_sub(max_skew).ok_or(JwtError::BadArgument("max clock skew too large".to_owned())));

        Ok(now_minus_a_bit)
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
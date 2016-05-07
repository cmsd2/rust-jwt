pub mod time;
pub mod expiry;
pub mod not_before;

/*
/// returns true if the claims are successfully verified
pub fn verify<C: Claims, T: SkewedTimeProvider>(c: &C, t: &T) -> JwtResult<bool> {
    let now_plus_a_bit = try!(t.now_utc_plus_a_bit());
    
    if let Some(expiry) = c.get_expiry_time() {
        if now_plus_a_bit.ge(&expiry) {
            return Ok(false);
        }
    }
    
    if let Some(not_before) = c.get_not_before_time() {
        if now_plus_a_bit.lt(&not_before) {
            return Ok(false);
        }
    }
    
    Ok(true)
}*/

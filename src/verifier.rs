use result::JwtResult;
use signer::Signer;
use header::Header;
use ring;

pub trait Verifier {
    /// "constant-time" signature verifier
    fn verify(&self, header: &Header, signing_input: &[u8], signature: &str) -> JwtResult<bool>;
}

impl<T> Verifier for T where T: Signer {
    fn verify(&self, header: &Header, signing_input: &[u8], signature: &str) -> JwtResult<bool> {
        let sig = try!(self.sign(header, signing_input));
        
        let result = ring::constant_time::verify_slices_are_equal(sig.as_bytes(), signature.as_bytes()).is_ok();
        
        Ok(result)
    }
}
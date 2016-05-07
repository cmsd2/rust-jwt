use result::JwtResult;
use signer::Signer;
use header::Header;
use rust_crypto::util::fixed_time_eq;

pub trait Verifier {
    /// "constant-time" signature verifier
    fn verify(&self, header: &Header, signing_input: &[u8], signature: &str) -> JwtResult<bool>;
}

impl<T> Verifier for T where T: Signer {
    fn verify(&self, header: &Header, signing_input: &[u8], signature: &str) -> JwtResult<bool> {
        let sig = try!(self.sign(header, signing_input));
        
        let result = fixed_time_eq(sig.as_bytes(), signature.as_bytes());
        
        Ok(result)
    }
}
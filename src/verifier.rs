use result::JwtResult;
use signer::Signer;
use header::Header;

pub trait Verifier {
    /// "constant-time" signature verifier
    fn verify(&self, header: &Header, signing_input: &[u8], signature: &str) -> JwtResult<bool>;
}

impl<T> Verifier for T where T: Signer {
    fn verify(&self, header: &Header, signing_input: &[u8], signature: &str) -> JwtResult<bool> {
        let sig = try!(self.sign(header, signing_input));
        
        Ok(sig == signature)
    }
}
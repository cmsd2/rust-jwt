use result::JwtResult;
use algorithm::Algorithm;
use header::Header;

pub trait Signer {
    fn sign(&self, header: &Header, signing_input: &[u8]) -> JwtResult<String>;
    
    fn has_algorithm(&self, a: Algorithm) -> bool;
}
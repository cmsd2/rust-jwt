#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

#![feature(test)]
extern crate test;
extern crate jsonwebtoken as jwt;
extern crate serde;

use jwt::{encode, decode};
use jwt::header::Header;
use jwt::crypto::mac_signer::MacSigner;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String
}

#[bench]
fn bench_encode(b: &mut test::Bencher) {
    let claim = Claims {
        sub: "b@b.com".to_owned(),
        company: "ACME".to_owned()
    };
    let signer = MacSigner::new("secret".as_bytes()).unwrap();

    b.iter(|| encode(Header::default(), &claim, &signer));
}

#[bench]
fn bench_decode(b: &mut test::Bencher) {
    let signer = MacSigner::new("secret".as_bytes()).unwrap();
    
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    b.iter(|| decode::<Claims, MacSigner>(token, &signer));
}
